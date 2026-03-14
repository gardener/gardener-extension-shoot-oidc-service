// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package trustconfigurator

import (
	"fmt"
	"time"

	configv1alpha1 "github.com/gardener/garden-shoot-trust-configurator/pkg/apis/config/v1alpha1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	gardenerkubernetes "github.com/gardener/gardener/pkg/client/kubernetes"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	monitoringutils "github.com/gardener/gardener/pkg/component/observability/monitoring/utils"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-shoot-oidc-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

const (
	// healthProbesPort is the port for health probes of the trust configurator extension
	healthProbesPort int32 = 8081
	// metricsPort is the port for metrics of the trust configurator extension
	metricsPort int32 = 8080
	// webhookPort is the port for webhooks of the trust configurator extension
	webhookPort int32 = 10250
	// virtualGardenPrefix is the prefix for virtual garden deployment
	virtualGardenPrefix = "virtual-garden-"
)

// trustConfiguratorCodec is the codec used to encode and decode the trust configurator configuration
var trustConfiguratorCodec runtime.Codec

func init() {
	trustConfiguratorScheme := runtime.NewScheme()
	utilruntime.Must(configv1alpha1.AddToScheme(trustConfiguratorScheme))

	ser := json.NewSerializerWithOptions(json.DefaultMetaFactory, trustConfiguratorScheme, trustConfiguratorScheme, json.SerializerOptions{
		Yaml: true,
	})
	versions := schema.GroupVersions([]schema.GroupVersion{configv1alpha1.SchemeGroupVersion})
	trustConfiguratorCodec = serializer.NewCodecFactory(trustConfiguratorScheme).CodecForVersions(ser, ser, versions, versions)
}

func getSourceResources(oidcConfig configv1alpha1.OIDCConfig, namespace, genericKubeconfigName, gardenAccessSecretName, serverTLSSecretName string) (map[string][]byte, error) {
	gardenShootTrustConfiguratorConfiguration := configv1alpha1.GardenShootTrustConfiguratorConfiguration{
		LogLevel:  "info",
		LogFormat: "json",
		Controllers: configv1alpha1.ControllerConfiguration{
			Shoot: configv1alpha1.ShootControllerConfig{
				SyncPeriod: &metav1.Duration{Duration: 1 * time.Hour},
				OIDCConfig: &configv1alpha1.OIDCConfig{
					Audiences:          oidcConfig.Audiences,
					MaxTokenExpiration: &metav1.Duration{Duration: oidcConfig.MaxTokenExpiration.Duration},
				},
			},
			GarbageCollector: configv1alpha1.GarbageCollectorControllerConfig{
				SyncPeriod:            &metav1.Duration{Duration: 1 * time.Hour},
				MinimumObjectLifetime: &metav1.Duration{Duration: 10 * time.Minute},
			},
		},
		LeaderElection: &componentbaseconfigv1alpha1.LeaderElectionConfiguration{
			LeaderElect:       ptr.To(true),
			LeaseDuration:     metav1.Duration{Duration: 15 * time.Second},
			RenewDeadline:     metav1.Duration{Duration: 10 * time.Second},
			RetryPeriod:       metav1.Duration{Duration: 2 * time.Second},
			ResourceLock:      "leases",
			ResourceName:      configv1alpha1.DefaultLockObjectName,
			ResourceNamespace: configv1alpha1.DefaultLockObjectNamespace,
		},
		Server: configv1alpha1.ServerConfiguration{
			HealthProbes: &configv1alpha1.Server{
				Port: int(healthProbesPort),
			},
			Metrics: &configv1alpha1.Server{
				Port: int(metricsPort),
			},
			Webhooks: configv1alpha1.HTTPSServer{
				Server: configv1alpha1.Server{
					Port: int(webhookPort),
				},
				TLS: configv1alpha1.TLS{
					ServerCertDir: constants.WebhookTLSCertDirGardenShootTrustConfigurator,
				},
			},
		},
	}
	configData, err := runtime.Encode(trustConfiguratorCodec, &gardenShootTrustConfiguratorConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to encode trust configurator configuration: %w", err)
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ConfigNameGardenShootTrustConfigurator,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": string(configData),
		},
	}

	image, err := imagevector.ImageVector().FindImage(constants.ImageNameGardenShootTrustConfigurator)
	if err != nil {
		return nil, fmt.Errorf("failed to find image version for %s: %v", constants.ImageNameGardenShootTrustConfigurator, err)
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationNameGardenShootTrustConfigurator,
			Namespace: namespace,
			Labels:    utils.MergeStringMaps(getLabels(), getHighAvailabilityLabel()),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             ptr.To[int32](1),
			RevisionHistoryLimit: ptr.To[int32](1),
			Selector:             &metav1.LabelSelector{MatchLabels: getLabels()},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS: v1beta1constants.LabelNetworkPolicyAllowed,
						gutil.NetworkPolicyLabel(virtualGardenPrefix+v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
					}),
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									TopologyKey:   corev1.LabelHostname,
									LabelSelector: &metav1.LabelSelector{MatchLabels: getLabels()},
								},
							}},
						},
					},
					AutomountServiceAccountToken: ptr.To(false),
					ServiceAccountName:           constants.ApplicationNameGardenShootTrustConfigurator,
					PriorityClassName:            v1beta1constants.PriorityClassNameGardenSystem300,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:            constants.ApplicationNameGardenShootTrustConfigurator,
						Image:           image.String(),
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
						},
						Args: []string{
							"--kubeconfig=" + gutil.PathGenericKubeconfig,
							"--config=" + fmt.Sprintf("%s/config.yaml", constants.ConfigPathGardenShootTrustConfigurator),
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "health",
								ContainerPort: healthProbesPort,
								Protocol:      "TCP",
							},
							{
								Name:          "metrics",
								ContainerPort: metricsPort,
								Protocol:      "TCP",
							},
							{
								Name:          "https",
								ContainerPort: webhookPort,
								Protocol:      "TCP",
							},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/readyz",
									Port:   intstr.FromInt32(healthProbesPort),
									Scheme: corev1.URISchemeHTTP,
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       10,
							FailureThreshold:    3,
							SuccessThreshold:    1,
							TimeoutSeconds:      5,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   intstr.FromInt32(healthProbesPort),
									Scheme: corev1.URISchemeHTTP,
								},
							},
							InitialDelaySeconds: 15,
							PeriodSeconds:       20,
							FailureThreshold:    3,
							SuccessThreshold:    1,
							TimeoutSeconds:      5,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      constants.WebhookTLSSecretNameGardenShootTrustConfigurator,
								ReadOnly:  true,
								MountPath: constants.WebhookTLSCertDirGardenShootTrustConfigurator,
							},
							{
								Name:      constants.ConfigNameGardenShootTrustConfigurator,
								ReadOnly:  true,
								MountPath: constants.ConfigPathGardenShootTrustConfigurator,
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: constants.WebhookTLSSecretNameGardenShootTrustConfigurator,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: serverTLSSecretName,
								},
							},
						},
						{
							Name: constants.ConfigNameGardenShootTrustConfigurator,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: constants.ConfigNameGardenShootTrustConfigurator,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := gutil.InjectGenericKubeconfig(deployment, genericKubeconfigName, gardenAccessSecretName); err != nil {
		return nil, err
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.ApplicationNameGardenShootTrustConfigurator,
			Namespace:   namespace,
			Labels:      getLabels(),
			Annotations: map[string]string{},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: getLabels(),
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt32(webhookPort),
				},
				{
					Name:       "metrics",
					Port:       metricsPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(metricsPort),
				},
			},
		},
	}

	metricsPort := networkingv1.NetworkPolicyPort{
		Port:     ptr.To(intstr.FromInt32(metricsPort)),
		Protocol: ptr.To(corev1.ProtocolTCP),
	}
	if err := gutil.InjectNetworkPolicyAnnotationsForGardenScrapeTargets(service, metricsPort); err != nil {
		return nil, err
	}

	webhookPort := networkingv1.NetworkPolicyPort{
		Port:     ptr.To(intstr.FromInt32(webhookPort)),
		Protocol: ptr.To(corev1.ProtocolTCP),
	}
	if err := gutil.InjectNetworkPolicyAnnotationsForWebhookTargets(service, webhookPort); err != nil {
		return nil, err
	}

	serviceMonitor := &monitoringv1.ServiceMonitor{
		ObjectMeta: monitoringutils.ConfigObjectMeta(constants.ApplicationNameGardenShootTrustConfigurator, namespace, "garden"),
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{MatchLabels: getLabels()},
			Endpoints: []monitoringv1.Endpoint{{
				Port:        "https",
				Scheme:      ptr.To(monitoringv1.SchemeHTTPS),
				HonorLabels: false,
				HTTPConfigWithProxyAndTLSFiles: monitoringv1.HTTPConfigWithProxyAndTLSFiles{
					HTTPConfigWithTLSFiles: monitoringv1.HTTPConfigWithTLSFiles{
						TLSConfig: &monitoringv1.TLSConfig{
							SafeTLSConfig: monitoringv1.SafeTLSConfig{
								InsecureSkipVerify: ptr.To(true),
							},
						},
					},
				},
				MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("garden_shoot_trust_configurator.+"),
			}},
		},
	}

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationNameGardenShootTrustConfigurator,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: getLabels()},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}
	registry := managedresources.NewRegistry(gardenerkubernetes.SeedScheme, gardenerkubernetes.SeedCodec, gardenerkubernetes.SeedSerializer)

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationNameGardenShootTrustConfigurator,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		AutomountServiceAccountToken: ptr.To(false),
	}
	vpa := buildVPA(namespace)

	resources, err := registry.AddAllAndSerialize(
		sa,
		configMap,
		pdb,
		deployment,
		vpa,
		service,
		serviceMonitor,
	)
	if err != nil {
		return nil, err
	}

	return resources, nil
}

func buildVPA(namespace string) *vpaautoscalingv1.VerticalPodAutoscaler {
	return &vpaautoscalingv1.VerticalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationNameGardenShootTrustConfigurator,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
			TargetRef: &autoscalingv1.CrossVersionObjectReference{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "Deployment",
				Name:       constants.ApplicationNameGardenShootTrustConfigurator,
			},
			UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{
				UpdateMode: ptr.To(vpaautoscalingv1.UpdateModeRecreate),
			},
			ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
				ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{{
					ContainerName:    vpaautoscalingv1.DefaultContainerResourcePolicy,
					ControlledValues: ptr.To(vpaautoscalingv1.ContainerControlledValuesRequestsOnly),
					MinAllowed: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				}},
			},
		},
	}
}

func getTargetResources(webhookCaBundle []byte, namespace, gardenAccessServiceAccountName string) (map[string][]byte, error) {
	failPolicy := admissionregistration.Fail
	sideEffectClass := admissionregistration.SideEffectClassNone
	validatingWebhookURL := fmt.Sprintf("https://%s.%s/webhooks/oidc", constants.ApplicationNameGardenShootTrustConfigurator, namespace)

	registry := managedresources.NewRegistry(gardenerkubernetes.GardenScheme, gardenerkubernetes.GardenCodec, gardenerkubernetes.GardenSerializer)
	result, err := registry.AddAllAndSerialize(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.ApplicationNameGardenShootTrustConfigurator,
				Labels: getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"authentication.gardener.cloud"},
					Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					Resources: []string{"openidconnects"},
				},
				{
					APIGroups: []string{"core.gardener.cloud"},
					Resources: []string{"shoots"},
					Verbs:     []string{"get", "list", "watch", "update", "patch"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.ApplicationNameGardenShootTrustConfigurator,
				Labels: getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     constants.ApplicationNameGardenShootTrustConfigurator,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      gardenAccessServiceAccountName,
					Namespace: metav1.NamespaceSystem,
				},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationNameGardenShootTrustConfigurator,
				Namespace: metav1.NamespaceSystem,
				Labels:    getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Verbs:     []string{"get", "list", "watch"},
					Resources: []string{"secrets"},
				},
				{
					APIGroups: []string{"coordination.k8s.io"},
					Resources: []string{"leases"},
					Verbs:     []string{"create", "list", "watch"},
				},
				{
					APIGroups:     []string{"coordination.k8s.io"},
					Resources:     []string{"leases"},
					ResourceNames: []string{configv1alpha1.DefaultLockObjectName},
					Verbs:         []string{"update", "get"},
				},
				{
					APIGroups: []string{""},
					Verbs:     []string{"create"},
					Resources: []string{"events"},
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationNameGardenShootTrustConfigurator,
				Namespace: metav1.NamespaceSystem,
				Labels:    getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     constants.ApplicationNameGardenShootTrustConfigurator,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      gardenAccessServiceAccountName,
					Namespace: metav1.NamespaceSystem,
				},
			},
		},
		&admissionregistration.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.ApplicationNameGardenShootTrustConfigurator,
				Labels: getLabels(),
			},
			Webhooks: []admissionregistration.ValidatingWebhook{{
				Name:                    "oidc.authentication.gardener.cloud",
				TimeoutSeconds:          ptr.To[int32](10),
				AdmissionReviewVersions: []string{"v1", "v1beta"},
				Rules: []admissionregistration.RuleWithOperations{{
					Operations: []admissionregistration.OperationType{admissionregistration.Update},
					Rule: admissionregistration.Rule{
						APIGroups:   []string{"authentication.gardener.cloud"},
						APIVersions: []string{"v1alpha1"},
						Resources:   []string{"openidconnects"},
					},
				}},
				FailurePolicy: &failPolicy,
				SideEffects:   &sideEffectClass,
				ObjectSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/managed-by": constants.ApplicationNameGardenShootTrustConfigurator,
					},
				},
				ClientConfig: admissionregistration.WebhookClientConfig{
					URL:      &validatingWebhookURL,
					CABundle: webhookCaBundle,
				},
			}},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize target resources: %w", err)
	}
	return result, nil
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name": constants.ApplicationNameGardenShootTrustConfigurator,
	}
}

func getHighAvailabilityLabel() map[string]string {
	return map[string]string{
		resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
	}
}

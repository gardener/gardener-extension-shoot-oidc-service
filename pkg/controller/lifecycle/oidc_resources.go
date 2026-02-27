// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	_ "embed"
	"fmt"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	gardenerkubernetes "github.com/gardener/gardener/pkg/client/kubernetes"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	monitoringutils "github.com/gardener/gardener/pkg/component/observability/monitoring/utils"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
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
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-shoot-oidc-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

//go:embed templates/authentication.gardener.cloud_openidconnects.yaml
var crdContent []byte

func getSeedResources(oidcReplicas *int32, namespace, genericKubeconfigName, shootAccessSecretName, serverTLSSecretName, kubeAPIServerDeploymentName string, extensionClass extensionsv1alpha1.ExtensionClass) (map[string][]byte, error) {
	var (
		priorityClassName        = v1beta1constants.PriorityClassNameShootControlPlane300
		allScrapeTargetsFn       = gutil.InjectNetworkPolicyAnnotationsForScrapeTargets
		serviceMonitorObjectMeta = monitoringutils.ConfigObjectMeta(constants.ApplicationName, namespace, "shoot")

		int10443      = int32(10443)
		port10443     = intstr.FromInt32(int10443)
		registry      = managedresources.NewRegistry(gardenerkubernetes.SeedScheme, gardenerkubernetes.SeedCodec, gardenerkubernetes.SeedSerializer)
		requestCPU    = resource.MustParse("10m")
		requestMemory = resource.MustParse("32Mi")
	)

	if extensionClass == extensionsv1alpha1.ExtensionClassGarden {
		priorityClassName = v1beta1constants.PriorityClassNameGardenSystem300
		allScrapeTargetsFn = gutil.InjectNetworkPolicyAnnotationsForGardenScrapeTargets
		serviceMonitorObjectMeta = monitoringutils.ConfigObjectMeta(constants.ApplicationName, namespace, "garden")
	}

	kubeConfig := &configv1.Config{
		Clusters: []configv1.NamedCluster{{
			Name: constants.ApplicationName,
			Cluster: configv1.Cluster{
				Server:                fmt.Sprintf("https://%s.%s/validate-token", constants.ApplicationName, namespace),
				CertificateAuthority:  fmt.Sprintf("%s/%s", constants.TokenValidatorDir, secretsutils.DataKeyCertificateBundle),
				InsecureSkipTLSVerify: false,
			},
		}},
		Contexts: []configv1.NamedContext{{
			Name: constants.ApplicationName,
			Context: configv1.Context{
				Cluster:  constants.ApplicationName,
				AuthInfo: constants.ApplicationName,
			},
		}},
		CurrentContext: constants.ApplicationName,
		AuthInfos: []configv1.NamedAuthInfo{{
			Name:     constants.ApplicationName,
			AuthInfo: configv1.AuthInfo{},
		}},
	}

	kubeAPIServerKubeConfig, err := runtime.Encode(configlatest.Codec, kubeConfig)
	if err != nil {
		return nil, err
	}

	image, err := imagevector.ImageVector().FindImage(constants.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to find image version for %s: %v", constants.ImageName, err)
	}

	oidcDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: namespace,
			Labels:    utils.MergeStringMaps(getLabels(), getHighAvailabilityLabel()),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             oidcReplicas,
			RevisionHistoryLimit: ptr.To[int32](1),
			Selector:             &metav1.LabelSelector{MatchLabels: getLabels()},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
					MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS:                                                   v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                        v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                       v1beta1constants.LabelNetworkPolicyAllowed,
						gutil.NetworkPolicyLabel(kubeAPIServerDeploymentName, kubeapiserverconstants.Port):         v1beta1constants.LabelNetworkPolicyAllowed,
						"networking.resources.gardener.cloud/to-all-istio-ingresses-istio-ingressgateway-tcp-9443": v1beta1constants.LabelNetworkPolicyAllowed,
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
					ServiceAccountName:           constants.ApplicationName,
					PriorityClassName:            priorityClassName,
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           image.String(),
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
						},
						Args: []string{
							"--kubeconfig=" + gutil.PathGenericKubeconfig,
							fmt.Sprintf("--tls-cert-file=%s/tls.crt", constants.WebhookTLSCertDir),
							fmt.Sprintf("--tls-private-key-file=%s/tls.key", constants.WebhookTLSCertDir),
							"--v=2",
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/readyz",
									Port:   port10443,
									Scheme: "HTTPS",
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       5,
							FailureThreshold:    3,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/livez",
									Port:   port10443,
									Scheme: "HTTPS",
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       20,
							FailureThreshold:    3,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    requestCPU,
								corev1.ResourceMemory: requestMemory,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "tls",
								ReadOnly:  true,
								MountPath: constants.WebhookTLSCertDir,
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: serverTLSSecretName,
								},
							},
						},
					},
				},
			},
		},
	}

	if err := gutil.InjectGenericKubeconfig(oidcDeployment, genericKubeconfigName, shootAccessSecretName); err != nil {
		return nil, err
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.ApplicationName,
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
					TargetPort: port10443,
				},
			},
		},
	}

	metricsPort := networkingv1.NetworkPolicyPort{
		Port:     ptr.To(intstr.FromInt32(int10443)),
		Protocol: ptr.To(corev1.ProtocolTCP),
	}
	if err := allScrapeTargetsFn(service, metricsPort); err != nil {
		return nil, err
	}
	if err := gutil.InjectNetworkPolicyAnnotationsForWebhookTargets(service, metricsPort); err != nil {
		return nil, err
	}

	serviceMonitor := &monitoringv1.ServiceMonitor{
		ObjectMeta: serviceMonitorObjectMeta,
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
				MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("oidc_webhook_authenticator_.+"),
			}},
		},
	}

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: getLabels()},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}

	resources, err := registry.AddAllAndSerialize(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: ptr.To(false),
		},
		pdb,
		oidcDeployment,
		buildVPA(namespace),
		service,
		serviceMonitor,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.WebhookKubeConfigSecretName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Data: map[string][]byte{
				"kubeconfig": kubeAPIServerKubeConfig,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getShootResources(webhookCaBundle []byte, namespace, shootAccessServiceAccountName string) (map[string][]byte, error) {
	failPolicy := admissionregistration.Fail
	sideEffectClass := admissionregistration.SideEffectClassNone
	validatingWebhookURL := fmt.Sprintf("https://%s.%s/webhooks/validating", constants.ApplicationName, namespace)

	shootRegistry := managedresources.NewRegistry(gardenerkubernetes.ShootScheme, gardenerkubernetes.ShootCodec, gardenerkubernetes.ShootSerializer)
	shootResources, err := shootRegistry.AddAllAndSerialize(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.OIDCResourceReader,
				Labels: getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"authentication.gardener.cloud"},
					Verbs:     []string{"get", "list", "watch"},
					Resources: []string{"openidconnects"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.OIDCResourceReader,
				Labels: getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     constants.OIDCResourceReader,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      shootAccessServiceAccountName,
					Namespace: metav1.NamespaceSystem,
				},
			},
		},
		&admissionregistration.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.WebhookConfigurationName,
				Labels: getLabels(),
			},
			Webhooks: []admissionregistration.ValidatingWebhook{{
				Name: "validation.oidc.service.extensions.gardener.cloud",
				Rules: []admissionregistration.RuleWithOperations{{
					Operations: []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
					Rule: admissionregistration.Rule{
						APIGroups:   []string{"authentication.gardener.cloud"},
						APIVersions: []string{"v1alpha1"},
						Resources:   []string{"openidconnects"},
					},
				}},
				FailurePolicy:           &failPolicy,
				SideEffects:             &sideEffectClass,
				AdmissionReviewVersions: []string{"v1", "v1beta"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					URL:      &validatingWebhookURL,
					CABundle: webhookCaBundle,
				},
			}},
		},
	)
	if err != nil {
		return nil, err
	}

	shootResources["crd.yaml"] = crdContent
	return shootResources, nil
}

func buildVPA(namespace string) *vpaautoscalingv1.VerticalPodAutoscaler {
	return &vpaautoscalingv1.VerticalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
			TargetRef: &autoscalingv1.CrossVersionObjectReference{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "Deployment",
				Name:       constants.ApplicationName,
			},
			UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{
				UpdateMode: ptr.To(vpaautoscalingv1.UpdateModeRecreate),
			},
			ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
				ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{{
					ContainerName:    vpaautoscalingv1.DefaultContainerResourcePolicy,
					ControlledValues: ptr.To(vpaautoscalingv1.ContainerControlledValuesRequestsOnly),
				}},
			},
		},
	}
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name": constants.ApplicationName,
	}
}

func getHighAvailabilityLabel() map[string]string {
	return map[string]string{
		resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
	}
}

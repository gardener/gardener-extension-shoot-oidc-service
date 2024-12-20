// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	gardenerkubernetes "github.com/gardener/gardener/pkg/client/kubernetes"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	monitoringutils "github.com/gardener/gardener/pkg/component/observability/monitoring/utils"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/retry"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/client-go/kubernetes"
	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"
)

const (
	// ActuatorName is the name of the OIDC Service actuator.
	ActuatorName        = constants.ServiceName + "-actuator"
	fakeTokenSecretName = constants.ApplicationName + "-fake-token" // <- TODO: remove this constant in a future release
)

//go:embed templates/authentication.gardener.cloud_openidconnects.yaml
var crdContent []byte

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, clientset kubernetes.Interface, config config.Configuration) extension.Actuator {
	return &actuator{
		client:        mgr.GetClient(),
		reader:        mgr.GetAPIReader(),
		decoder:       serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		clientset:     clientset,
		serviceConfig: config,
	}
}

type actuator struct {
	client        client.Client
	reader        client.Reader
	clientset     kubernetes.Interface
	decoder       runtime.Decoder
	serviceConfig config.Configuration
}

func getOIDCReplicas(ctx context.Context, c client.Client, namespace string, hibernated bool) (*int32, error) {
	// Scale to 0 if cluster is hibernated
	if hibernated {
		return ptr.To[int32](0), nil
	}

	oidcDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: namespace,
		},
	}

	err := c.Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)

	var initialCount int32 = 2
	switch {
	case err != nil && apierrors.IsNotFound(err):
		// Scale to initial replica count
		return &initialCount, nil
	case err != nil:
		// Error cannot be handled here so pass it to the caller function
		return ptr.To[int32](0), err
	case oidcDeployment.Spec.Replicas != nil && *oidcDeployment.Spec.Replicas > 0:
		// Do not interfere with hpa recommendations
		return oidcDeployment.Spec.Replicas, nil
	case oidcDeployment.Spec.Replicas != nil && *oidcDeployment.Spec.Replicas == 0:
		// Wake up oidc deployment with initial replica count
		return &initialCount, nil
	default:
		return &initialCount, nil
	}
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	oidcShootAccessSecret := gutil.NewShootAccessSecret(gutil.SecretNamePrefixShootAccess+constants.ApplicationName, namespace)
	if err := oidcShootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	hibernated := controller.IsHibernationEnabled(cluster)
	oidcReplicas, err := getOIDCReplicas(ctx, a.client, namespace, hibernated)
	if err != nil {
		return err
	}

	// initialize SecretsManager based on Cluster object
	configs := secrets.ConfigsFor(namespace)

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, configs)
	if err != nil {
		return err
	}

	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, secretsManager, configs)
	if err != nil {
		return err
	}

	caBundleSecret, found := secretsManager.Get(secrets.CAName)
	if !found {
		return fmt.Errorf("secret %q not found", secrets.CAName)
	}

	seedResources, err := getSeedResources(
		oidcReplicas,
		hibernated,
		namespace,
		extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		oidcShootAccessSecret.Secret.Name,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
	)
	if err != nil {
		return err
	}

	shootResources, err := getShootResources(
		caBundleSecret.Data[secretutils.DataKeyCertificateBundle],
		namespace,
		oidcShootAccessSecret.ServiceAccountName,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot, constants.ServiceName, false, shootResources); err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesSeed, false, seedResources); err != nil {
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	oidcDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: namespace,
		},
	}
	timeoutRoulloutCtx, cancelWaitRollout := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelWaitRollout()
	if err := retry.Until(timeoutRoulloutCtx, 5*time.Second, health.IsDeploymentUpdated(a.reader, oidcDeployment)); err != nil {
		return err
	}

	// patch deployment for kube-apiserver in order to trigger webhook
	depl := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      v1beta1constants.DeploymentNameKubeAPIServer,
		},
	}

	if err := a.client.Patch(ctx, depl, client.RawPatch(types.StrategicMergePatchType, []byte("{}"))); err != nil {
		return err
	}

	// TODO: remove this in a future release
	if err := a.deleteSecret(ctx, fakeTokenSecretName, namespace); err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, false)
}

// delete deletes the resources deployed for the extension.
// It can be configured to skip deletion of the secretes managed by the SecretsManager.
func (a *actuator) delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretsManagerSecrets bool) error {
	namespace := ex.GetNamespace()
	twoMinutes := 2 * time.Minute

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()

	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutSeedCtx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	timeoutShootCtx, cancelShootCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelShootCtx()

	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutShootCtx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	for _, name := range []string{
		gutil.SecretNamePrefixShootAccess + constants.TokenValidator, // <- TODO: remove the secret name in a future version
		gutil.SecretNamePrefixShootAccess + constants.ApplicationName,
		fakeTokenSecretName, // <- TODO: remove the secret name in a future release
	} {
		if err := a.deleteSecret(ctx, name, namespace); err != nil {
			return err
		}
	}

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	if skipSecretsManagerSecrets {
		return nil
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
	if err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

func (a *actuator) deleteSecret(ctx context.Context, name, namespace string) error {
	return client.IgnoreNotFound(a.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}))
}

// ForceDelete the Extension resource.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, log, ex)
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ManagedResourceNamesShoot, true); err != nil {
		return err
	}

	// SecretsManager secrets should not be deleted during migration in order to have the required ones
	// persisted in the shootstate resource.
	return a.delete(ctx, log, ex, true)
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

func getSeedResources(oidcReplicas *int32, hibernated bool, namespace, genericKubeconfigName, shootAccessSecretName, serverTLSSecretName string) (map[string][]byte, error) {
	var (
		int10443      = int32(10443)
		port10443     = intstr.FromInt32(int10443)
		registry      = managedresources.NewRegistry(gardenerkubernetes.SeedScheme, gardenerkubernetes.SeedCodec, gardenerkubernetes.SeedSerializer)
		requestCPU    = resource.MustParse("10m")
		requestMemory = resource.MustParse("32Mi")
	)

	kubeConfig := &configv1.Config{
		Clusters: []configv1.NamedCluster{{
			Name: constants.ApplicationName,
			Cluster: configv1.Cluster{
				Server:                fmt.Sprintf("https://%s.%s/validate-token", constants.ApplicationName, namespace),
				CertificateAuthority:  fmt.Sprintf("%s/%s", constants.TokenValidatorDir, secretutils.DataKeyCertificateBundle),
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

	if err := registry.Add(buildPDB(namespace)); err != nil {
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
						v1beta1constants.LabelNetworkPolicyToDNS:                                                            v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                                 v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                                v1beta1constants.LabelNetworkPolicyAllowed,
						gutil.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
						"networking.resources.gardener.cloud/to-all-istio-ingresses-istio-ingressgateway-tcp-9443":          v1beta1constants.LabelNetworkPolicyAllowed,
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
					PriorityClassName:            v1beta1constants.PriorityClassNameShootControlPlane300,
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           image.String(),
						ImagePullPolicy: corev1.PullIfNotPresent,
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

	if !hibernated {
		err = registry.Add(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.WebhookKubeConfigSecretName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Data: map[string][]byte{
				"kubeconfig": kubeAPIServerKubeConfig,
			},
		})
		if err != nil {
			return nil, err
		}
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
	if err := gutil.InjectNetworkPolicyAnnotationsForScrapeTargets(service, metricsPort); err != nil {
		return nil, err
	}
	if err := gutil.InjectNetworkPolicyAnnotationsForWebhookTargets(service, metricsPort); err != nil {
		return nil, err
	}

	serviceMonitor := &monitoringv1.ServiceMonitor{
		ObjectMeta: monitoringutils.ConfigObjectMeta(constants.ApplicationName, namespace, "shoot"),
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{MatchLabels: getLabels()},
			Endpoints: []monitoringv1.Endpoint{{
				Port:                 "https",
				Scheme:               "https",
				HonorLabels:          false,
				TLSConfig:            &monitoringv1.TLSConfig{SafeTLSConfig: monitoringv1.SafeTLSConfig{InsecureSkipVerify: ptr.To(true)}},
				MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("oidc_webhook_authenticator_.+"),
			}},
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
		oidcDeployment,
		buildVPA(namespace),
		service,
		serviceMonitor,
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func buildPDB(namespace string) client.Object {
	var (
		pdb = &policyv1.PodDisruptionBudget{
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
	)

	return pdb
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
				UpdateMode: ptr.To(vpaautoscalingv1.UpdateModeAuto),
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

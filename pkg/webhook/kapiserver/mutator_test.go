// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

var _ = Describe("Mutator", func() {
	const (
		namespace     = "test"
		cacheElement  = "--authentication-token-webhook-cache-ttl=0"
		configElement = "--authentication-token-webhook-config-file=/var/run/secrets/oidc-webhook/authenticator/kubeconfig"
	)

	var (
		ctx        = context.Background()
		fakeClient client.Client
		sm         secretsmanager.Interface

		oidcAuthenticatorKubeConfigVolumeMount = corev1.VolumeMount{
			Name:      oidcAuthenticatorKubeConfigVolumeName,
			ReadOnly:  true,
			MountPath: "/var/run/secrets/oidc-webhook/authenticator",
		}
		oidcAuthenticatorKubeConfigVolume = corev1.Volume{
			Name: oidcAuthenticatorKubeConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.WebhookKubeConfigSecretName,
				},
			},
		}
		tokenValidatorSecretVolumeMount = corev1.VolumeMount{
			Name:      tokenValidatorSecretVolumeName,
			ReadOnly:  true,
			MountPath: "/var/run/secrets/oidc-webhook/token-validator",
		}
		tokenValidatorSecretVolume = corev1.Volume{
			Name: tokenValidatorSecretVolumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: pointer.Int32(420),
					Sources: []corev1.VolumeProjection{
						{
							Secret: &corev1.SecretProjection{
								Items: []corev1.KeyToPath{
									{Key: "bundle.crt", Path: "bundle.crt"},
								},
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "ca-extension-shoot-oidc-service",
								},
							},
						},
						{
							Secret: &corev1.SecretProjection{
								Items: []corev1.KeyToPath{
									{Key: "token", Path: "token"},
								},
								LocalObjectReference: corev1.LocalObjectReference{
									Name: gutil.SecretNamePrefixShootAccess + constants.ApplicationName + "-token-validator",
								},
							},
						},
					},
				},
			},
		}

		checkDeploymentIsCorrectlyMutated = func(deployment *appsv1.Deployment) {
			// Check that the kube-apiserver container still exists
			c := extensionswebhook.ContainerWithName(deployment.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
			Expect(c).To(Not(BeNil()))

			Expect(c.Command).To(ContainElement(cacheElement))
			Expect(c.Command).To(ContainElement(configElement))

			Expect(c.VolumeMounts).To(ContainElement(oidcAuthenticatorKubeConfigVolumeMount))
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(oidcAuthenticatorKubeConfigVolume))

			Expect(c.VolumeMounts).To(ContainElement(tokenValidatorSecretVolumeMount))
			Expect(deployment.Spec.Template.Spec.Volumes).To(ContainElement(tokenValidatorSecretVolume))
		}
		checkDeploymentIsNotMutated = func(deployment *appsv1.Deployment) {
			// Check that the kube-apiserver container still exists
			c := extensionswebhook.ContainerWithName(deployment.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
			Expect(c).To(Not(BeNil()))

			for _, v := range c.Command {
				Expect(strings.HasPrefix(v, oidcWebhookConfigPrefix)).To(BeFalse())
				Expect(strings.HasPrefix(v, oidcWebhookCacheTTLPrefix)).To(BeFalse())
			}

			for _, v := range c.VolumeMounts {
				Expect(v.Name).NotTo(Equal(oidcAuthenticatorKubeConfigVolumeName))
				Expect(v.Name).NotTo(Equal(tokenValidatorSecretVolumeName))
			}

			for _, v := range deployment.Spec.Template.Spec.Volumes {
				Expect(v.Name).NotTo(Equal(oidcAuthenticatorKubeConfigVolumeName))
				Expect(v.Name).NotTo(Equal(tokenValidatorSecretVolumeName))

				// Ensure no volume source with the oidc config related secrets are present
				if v.VolumeSource.Secret != nil {
					Expect(v.VolumeSource.Secret.SecretName).NotTo(Equal(constants.WebhookKubeConfigSecretName))
				}

				if v.VolumeSource.Projected != nil && len(v.VolumeSource.Projected.Sources) > 0 {
					for _, s := range v.VolumeSource.Projected.Sources {
						if s.Secret != nil {
							Expect(s.Secret.LocalObjectReference.Name).NotTo(Equal(gutil.SecretNamePrefixShootAccess + constants.ApplicationName + "-token-validator"))
						}
					}
				}
			}
		}

		encode = func(obj runtime.Object) []byte {
			bytes, err := json.Marshal(obj)
			Expect(err).NotTo(HaveOccurred())
			return bytes
		}

		getCluster = func(hibernated bool) *extensionsv1alpha1.Cluster {
			return &extensionsv1alpha1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
				Spec: extensionsv1alpha1.ClusterSpec{
					Shoot: runtime.RawExtension{
						Raw: encode(&gardencorev1beta1.Shoot{
							TypeMeta: metav1.TypeMeta{
								Kind:       "Shoot",
								APIVersion: "core.gardener.cloud/v1beta1",
							},
							ObjectMeta: metav1.ObjectMeta{
								Name: "some-cluster",
							},
							Spec: gardencorev1beta1.ShootSpec{
								Hibernation: &gardencorev1beta1.Hibernation{
									Enabled: &hibernated,
								},
							},
						}),
					},
				},
			}
		}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		sm = fakesecretsmanager.New(fakeClient, namespace)
	})

	Describe("MutateKubeAPIServerDeployments", func() {
		var (
			deployment *appsv1.Deployment
			ensurer    genericmutator.Ensurer
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: v1beta1constants.DeploymentNameKubeAPIServer,
								},
							},
						},
					},
				},
				Status: appsv1.DeploymentStatus{
					ReadyReplicas: 1,
				},
			}

			ensurer = NewEnsurer(logger)
			Expect(ensurer.(inject.Client).InjectClient(fakeClient)).To(Succeed())
		})

		It("should add missing flags to a kube-apiserver pod", func() {
			oldNewSecretsManager := NewSecretsManager
			NewSecretsManager = func(_ context.Context, _ logr.Logger, _ clock.Clock, _ client.Client, _ *extensionscontroller.Cluster, _ string, _ []extensionssecretsmanager.SecretConfigWithOptions) (secretsmanager.Interface, error) {
				return sm, nil
			}
			defer func() { NewSecretsManager = oldNewSecretsManager }()

			Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookKubeConfigSecretName}})).To(Succeed())
			Expect(fakeClient.Create(ctx, getCluster(false))).To(Succeed())

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should modify existing elements of a pod", func() {
			deployment.Spec.Template.Spec.Containers[0].Command = []string{
				"--authentication-token-webhook-cache-ttl=?",
				"--authentication-token-webhook-config-file=?",
			}

			oldNewSecretsManager := NewSecretsManager
			NewSecretsManager = func(_ context.Context, _ logr.Logger, _ clock.Clock, _ client.Client, _ *extensionscontroller.Cluster, _ string, _ []extensionssecretsmanager.SecretConfigWithOptions) (secretsmanager.Interface, error) {
				return sm, nil
			}
			defer func() { NewSecretsManager = oldNewSecretsManager }()

			Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookKubeConfigSecretName}})).To(Succeed())
			Expect(fakeClient.Create(ctx, getCluster(false))).To(Succeed())

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)).To(Succeed())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should not add oidc configs to a kube-apiserver pod if kube-apiserver deployment does not have ready replicas", func() {
			Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookKubeConfigSecretName}})).To(Succeed())
			Expect(fakeClient.Create(ctx, getCluster(false))).To(Succeed())

			deployment.Status.ReadyReplicas = 0
			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not add oidc configs to a kube-apiserver pod if webhook secret does not exist", func() {
			Expect(fakeClient.Create(ctx, getCluster(false))).To(Succeed())

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not add oidc configs to a kube-apiserver pod if webhook secret exists but cluster is hibernated", func() {
			Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookKubeConfigSecretName}})).To(Succeed())
			Expect(fakeClient.Create(ctx, getCluster(true))).To(Succeed())

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)).To(Succeed())
			checkDeploymentIsNotMutated(deployment)
		})
	})
})

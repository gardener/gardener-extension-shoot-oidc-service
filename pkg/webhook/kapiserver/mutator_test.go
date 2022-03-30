// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"

	"github.com/golang/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

var _ = Describe("Mutator", func() {

	const (
		namespace     = "test"
		cacheElement  = "--authentication-token-webhook-cache-ttl=0"
		configElement = "--authentication-token-webhook-config-file=/var/run/secrets/oidc-webhook/authenticator/kubeconfig"
	)

	var (
		ctrl *gomock.Controller
		ctx  = context.Background()

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
									{Key: "ca.crt", Path: "ca.crt"},
								},
								LocalObjectReference: corev1.LocalObjectReference{
									Name: v1beta1constants.SecretNameCACluster,
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

		getCluster = func(hibernated bool) interface{} {
			return func(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
				*obj.(*extensionsv1alpha1.Cluster) = extensionsv1alpha1.Cluster{
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

				return nil
			}
		}
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("MutateKubeAPIServerDeployments", func() {
		var (
			client               *mockclient.MockClient
			deployment           *appsv1.Deployment
			ensurer              genericmutator.Ensurer
			secretNamespacedName = types.NamespacedName{
				Namespace: namespace,
				Name:      constants.WebhookKubeConfigSecretName,
			}
			clusterNamespacedName = types.NamespacedName{
				// cluster is named after the namespace
				Name: "test",
			}
			errNotFound = &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonNotFound}}
			errInternal = fmt.Errorf("internal error")
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

			client = mockclient.NewMockClient(ctrl)

			ensurer = NewEnsurer(logger)
			err := ensurer.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing flags to a kube-apiserver pod", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
			client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(false))
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should modify existing elements of a pod", func() {
			deployment.Spec.Template.Spec.Containers[0].Command = []string{
				"--authentication-token-webhook-cache-ttl=?",
				"--authentication-token-webhook-config-file=?",
			}

			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
			client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(false))
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsCorrectlyMutated(deployment)
		})

		It("should not add flags to a kube-apiserver pod if webhook secret does not exist", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(errNotFound)
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not add oidc configs to a kube-apiserver pod if webhook secret exists but cluster is hibernated", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
			client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(true))
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).NotTo(HaveOccurred())
			checkDeploymentIsNotMutated(deployment)
		})

		It("should not add oidc configs to a kube-apiserver pod and return error if fails to get webhook secret and error is different from not found", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(errInternal)
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(errInternal.Error()))
			checkDeploymentIsNotMutated(deployment)
		})

		// It("should remove oidc configs when secret is deleted", func() {
		// 	client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
		// 	client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(false))
		// 	err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
		// 	Expect(err).NotTo(HaveOccurred())
		// 	checkDeploymentIsCorrectlyMutated(deployment)

		// 	client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(errNotFound)
		// 	err = ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
		// 	Expect(err).NotTo(HaveOccurred())
		// 	checkDeploymentIsNotMutated(deployment)
		// })

		// It("should remove oidc configs when cluster is hibernated", func() {
		// 	client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
		// 	client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(false))
		// 	err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
		// 	Expect(err).NotTo(HaveOccurred())
		// 	checkDeploymentIsCorrectlyMutated(deployment)

		// 	client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
		// 	client.EXPECT().Get(ctx, clusterNamespacedName, &extensionsv1alpha1.Cluster{}).DoAndReturn(getCluster(true))
		// 	err = ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
		// 	Expect(err).NotTo(HaveOccurred())
		// 	checkDeploymentIsNotMutated(deployment)
		// })
	})
})

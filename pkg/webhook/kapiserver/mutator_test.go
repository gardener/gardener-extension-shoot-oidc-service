// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

		checkDeploymentIsCorrectlyMutated = func(deployment *appsv1.Deployment) {
			// Check that the kube-apiserver container still exists
			c := extensionswebhook.ContainerWithName(deployment.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
			Expect(c).To(Not(BeNil()))

			Expect(c.Command).To(ContainElement(cacheElement))
			Expect(c.Command).To(ContainElement(configElement))
		}
		checkDeploymentIsNotMutated = func(deployment *appsv1.Deployment) {
			// Check that the kube-apiserver container still exists
			c := extensionswebhook.ContainerWithName(deployment.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
			Expect(c).To(Not(BeNil()))

			Expect(c.Command).NotTo(ContainElement(cacheElement))
			Expect(c.Command).NotTo(ContainElement(configElement))
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
			}

			client = mockclient.NewMockClient(ctrl)

			ensurer = NewEnsurer(logger)
			err := ensurer.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing flags to a kube-apiserver pod", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(nil)
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

		It("should not add flags to a kube-apiserver pod and return error if fails to get webhook secret and error is different from not found", func() {
			client.EXPECT().Get(ctx, secretNamespacedName, gomock.AssignableToTypeOf(&corev1.Secret{})).Return(errInternal)
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, nil, deployment, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(errInternal.Error()))
			checkDeploymentIsNotMutated(deployment)
		})
	})
})

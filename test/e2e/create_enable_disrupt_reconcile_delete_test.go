// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"fmt"
	"time"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	tf "github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("OIDC Extension Tests", Label("OIDC"), func() {
	f := defaultShootCreationFramework()
	f.Shoot = defaultShoot("e2e-disrupted")

	It("Create Shoot, Enable OIDC Extension, Disrupt API Server, Reconcile and Delete Shoot", Label("bad-case"), func() {
		By("Create Shoot")
		ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.CreateShootAndWaitForCreation(ctx, false)).To(Succeed())
		f.Verify()

		By("Enable OIDC Extension")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.UpdateShoot(ctx, f.Shoot, ensureOIDCServiceIsEnabled)).To(Succeed())

		_, seedClient, err := f.GetSeed(ctx, *f.Shoot.Status.SeedName)
		Expect(err).NotTo(HaveOccurred())
		project, err := f.GetShootProject(ctx, f.Shoot.Namespace)
		Expect(err).NotTo(HaveOccurred())
		shootSeedNamespace := tf.ComputeTechnicalID(project.Name, f.Shoot)

		depl, err := getOIDCDeployment(ctx, seedClient.Client(), shootSeedNamespace)
		Expect(err).NotTo(HaveOccurred())
		one := int32(1)
		Expect(*depl.Spec.Replicas).To(BeNumerically(">=", one))
		Expect(depl.Status.ReadyReplicas).To(BeNumerically(">=", one))

		By("Disrupt API Server")
		ctx, cancel = context.WithTimeout(parentCtx, 10*time.Minute)
		defer cancel()
		Expect(breakAPIServerDepl(ctx, seedClient.Client(), shootSeedNamespace)).To(Succeed())
		Eventually(func() error {
			return ensureNoRunningKubeAPIServerContainers(ctx, seedClient.Client(), shootSeedNamespace)
		}, time.Minute*2, time.Second*2).Should(Succeed())
		Expect(seedClient.Client().Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-access-oidc-webhook-authenticator-token-validator",
				Namespace: shootSeedNamespace,
			},
		}, &client.DeleteOptions{})).To(Succeed())

		By("Reconcile Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.UpdateShoot(ctx, f.Shoot, addReconcileAnnotation)).To(Succeed())

		By("Delete Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
	})
})

func breakAPIServerDepl(ctx context.Context, c client.Client, namespace string) error {
	kubeAPIServerDepl := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver",
			Namespace: namespace,
		},
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(kubeAPIServerDepl), kubeAPIServerDepl); err != nil {
		return err
	}
	for i, v := range kubeAPIServerDepl.Spec.Template.Spec.Containers {
		if v.Name == "kube-apiserver" {
			kubeAPIServerDepl.Spec.Template.Spec.Containers[i].Command = append(kubeAPIServerDepl.Spec.Template.Spec.Containers[i].Command, "--hello-world=invalid-flag")
			break
		}
	}
	if err := c.Update(ctx, kubeAPIServerDepl, &client.UpdateOptions{}); err != nil {
		return err
	}

	labels := client.MatchingLabels{
		v1beta1constants.GardenRole: "controlplane",
		"role":                      "apiserver",
	}

	replicaSet := &appsv1.ReplicaSet{}
	return c.DeleteAllOf(ctx, replicaSet, client.InNamespace(namespace), labels)
}

func ensureNoRunningKubeAPIServerContainers(ctx context.Context, c client.Client, namespace string) error {
	labels := client.MatchingLabels{
		v1beta1constants.GardenRole: "controlplane",
		"role":                      "apiserver",
	}

	pods := &corev1.PodList{}
	if err := c.List(ctx, pods, client.InNamespace(namespace), labels); err != nil {
		return err
	}

	for _, p := range pods.Items {
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == "kube-apiserver" && (c.State.Waiting == nil || c.State.Waiting.Reason != "CrashLoopBackOff") {
				return fmt.Errorf("there are still healty kube-apiserver containers running")
			}
		}
	}
	return nil
}

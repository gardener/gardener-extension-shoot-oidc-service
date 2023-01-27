// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"time"

	tf "github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Extension Tests", Label("OIDC"), func() {
	f := defaultShootCreationFramework()
	f.Shoot = defaultShoot("e2e-hibernated")

	It("Create Shoot, Enable OIDC Extension, Hibernate and Delete Shoot", Label("good-case"), func() {
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

		By("Hibernate Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 10*time.Minute)
		defer cancel()
		Expect(f.HibernateShoot(ctx, f.Shoot)).To(Succeed())

		depl, err = getOIDCDeployment(ctx, seedClient.Client(), shootSeedNamespace)
		Expect(err).NotTo(HaveOccurred())
		zero := int32(0)
		Expect(*depl.Spec.Replicas).To(BeNumerically("==", zero))

		By("Delete Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
	})
})

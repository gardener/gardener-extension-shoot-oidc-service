// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

/**
	Overview
		- Tests the health checks for the shoot-oidc-service extension.
	Prerequisites
		- A Shoot exists.
	Test-case:
		1) Extension CRD
			1.1) HealthCondition Type: ShootControlPlaneHealthy
				-  update the ManagedResource 'extension-shoot-oidc-service-seed' and verify the health check conditions in the Extension CRD status.
			1.2) HealthCondition Type: ShootSystemComponentsHealthy
				-  update the ManagedResource 'extension-shoot-oidc-service-shoot' and verify the health check conditions in the Extension CRD status.
 **/

package healthcheck

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	healthcheckoperation "github.com/gardener/gardener/extensions/test/integration/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/test/framework"
	"github.com/onsi/ginkgo"
)

const (
	timeout = 5 * time.Minute
)

var _ = ginkgo.Describe("Extension-shoot-oidc-service integration test: health checks", func() {
	f := framework.NewShootFramework(nil)

	ginkgo.Context("Extension", func() {
		ginkgo.Context("Condition type: ShootControlPlaneHealthy", func() {
			f.Serial().Release().CIt(fmt.Sprintf("Extension CRD should contain unhealthy condition due to ManagedResource '%s' is unhealthy", constants.ManagedResourceNamesSeed), func(ctx context.Context) {
				err := healthcheckoperation.ExtensionHealthCheckWithManagedResource(ctx, timeout, f, "shoot-oidc-service", constants.ManagedResourceNamesSeed, gardencorev1beta1.ShootControlPlaneHealthy)
				framework.ExpectNoError(err)
			}, timeout)
		})

		ginkgo.Context("Condition type: ShootSystemComponentsHealthy", func() {
			f.Serial().Release().CIt(fmt.Sprintf("Extension CRD should contain unhealthy condition due to ManagedResource '%s' is unhealthy", constants.ManagedResourceNamesShoot), func(ctx context.Context) {
				err := healthcheckoperation.ExtensionHealthCheckWithManagedResource(ctx, timeout, f, "shoot-oidc-service", constants.ManagedResourceNamesShoot, gardencorev1beta1.ShootSystemComponentsHealthy)
				framework.ExpectNoError(err)
			}, timeout)
		})
	})
})

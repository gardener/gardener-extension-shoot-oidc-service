// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// GardenShootTrustConfiguratorExtensionType is the name of the garden-shoot-trust-configurator extension type.
	GardenShootTrustConfiguratorExtensionType = "garden-shoot-trust-configurator"
	// GardenShootTrustConfiguratorServiceName is the name of the service for the trust configurator extension.
	GardenShootTrustConfiguratorServiceName = GardenShootTrustConfiguratorExtensionType

	gardenShootTrustConfiguratorServiceName = "extension-" + GardenShootTrustConfiguratorServiceName
	// GardenShootTrustConfiguratorManagedResourceNamesSource is the name used to describe the managed runtime resources for the trust configurator.
	GardenShootTrustConfiguratorManagedResourceNamesSource = gardenShootTrustConfiguratorServiceName + "-runtime"
	// GardenShootTrustConfiguratorManagedResourceNamesTarget is the name used to describe the managed virtual garden resources for the trust configurator.
	GardenShootTrustConfiguratorManagedResourceNamesTarget = gardenShootTrustConfiguratorServiceName + "-virtual-garden"

	// GardenShootTrustConfiguratorApplicationName is the name for resources describing the components deployed by the trust configurator extension controller.
	GardenShootTrustConfiguratorApplicationName = "garden-shoot-trust-configurator"
	// GardenShootTrustConfiguratorImageName is the name of the garden-shoot-trust-configurator image.
	GardenShootTrustConfiguratorImageName = GardenShootTrustConfiguratorApplicationName

	// GardenShootTrustConfiguratorWebhookTLSSecretName is the name of the TLS secret resource used by the trust configurator webhook in the runtime cluster.
	GardenShootTrustConfiguratorWebhookTLSSecretName = GardenShootTrustConfiguratorApplicationName + "-tls"
	// GardenShootTrustConfiguratorWebhookTLSCertDir is the directory used for mounting the trust configurator webhook certificates.
	GardenShootTrustConfiguratorWebhookTLSCertDir = "/etc/garden-shoot-trust-configurator/webhooks/tls"

	// GardenShootTrustConfiguratorConfigName is the name of the config resource used by the trust configurator.
	GardenShootTrustConfiguratorConfigName = GardenShootTrustConfiguratorApplicationName + "-config"
	// GardenShootTrustConfiguratorConfigPath is the directory used for mounting the trust configurator config.
	GardenShootTrustConfiguratorConfigPath = "/etc/garden-shoot-trust-configurator/config"
)

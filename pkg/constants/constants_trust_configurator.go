// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ExtensionTypeGardenShootTrustConfigurator is the name of the garden-shoot-trust-configurator extension type.
	ExtensionTypeGardenShootTrustConfigurator = "garden-shoot-trust-configurator"
	// ServiceNameGardenShootTrustConfigurator is the name of the service for the trust configurator extension.
	ServiceNameGardenShootTrustConfigurator = ExtensionTypeGardenShootTrustConfigurator

	gardenShootTrustConfiguratorServiceName = "extension-" + ServiceNameGardenShootTrustConfigurator
	// ManagedResourceNamesSeedGardenShootTrustConfigurator is the name used to describe the managed seed resources for the trust configurator.
	ManagedResourceNamesSeedGardenShootTrustConfigurator = gardenShootTrustConfiguratorServiceName + "-seed"
	// ManagedResourceNamesVirtualGardenGardenShootTrustConfigurator is the name used to describe the managed virtual garden resources for the trust configurator.
	ManagedResourceNamesVirtualGardenGardenShootTrustConfigurator = gardenShootTrustConfiguratorServiceName + "-virtual-garden"

	// ApplicationNameGardenShootTrustConfigurator is the name for resources describing the components deployed by the trust configurator extension controller.
	ApplicationNameGardenShootTrustConfigurator = "garden-shoot-trust-configurator"
	// ImageNameGardenShootTrustConfigurator is the name of the garden-shoot-trust-configurator image.
	ImageNameGardenShootTrustConfigurator = ApplicationNameGardenShootTrustConfigurator

	// WebhookTLSSecretNameGardenShootTrustConfigurator is the name of the TLS secret resource used by the trust configurator webhook in the seed cluster.
	WebhookTLSSecretNameGardenShootTrustConfigurator = ApplicationNameGardenShootTrustConfigurator + "-tls"
	// WebhookTLSCertDirGardenShootTrustConfigurator is the directory used for mounting the trust configurator webhook certificates.
	WebhookTLSCertDirGardenShootTrustConfigurator = "/etc/garden-shoot-trust-configurator/webhooks/tls"

	// ConfigNameGardenShootTrustConfigurator is the name of the config resource used by the trust configurator.
	ConfigNameGardenShootTrustConfigurator = ApplicationNameGardenShootTrustConfigurator + "-config"
	// ConfigPathGardenShootTrustConfigurator is the directory used for mounting the trust configurator config.
	ConfigPathGardenShootTrustConfigurator = "/etc/garden-shoot-trust-configurator/config"
)

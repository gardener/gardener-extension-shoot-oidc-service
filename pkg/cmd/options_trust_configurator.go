// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	configv1alpha1 "github.com/gardener/garden-shoot-trust-configurator/pkg/apis/config/v1alpha1"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustconfigurator "github.com/gardener/gardener-extension-shoot-oidc-service/pkg/controller/trust-configurator"
)

// TrustConfiguratorOptions holds command-line options for the trust-configurator controller responsible for OIDC resource management.
type TrustConfiguratorOptions struct {
	// ControllerConfig holds the completed generic controller configuration.
	controllercmd.ControllerOptions
	// OIDCConfig holds the OIDC configuration for the OIDC resourcess
	OIDCConfig configv1alpha1.OIDCConfig

	config *TrustConfiguratorConfig
}

// AddFlags implements Flagger.AddFlags.
func (o *TrustConfiguratorOptions) AddFlags(fs *pflag.FlagSet) {
	o.ControllerOptions.AddFlags(fs)
	if o.OIDCConfig.MaxTokenExpiration == nil {
		o.OIDCConfig.MaxTokenExpiration = &metav1.Duration{Duration: configv1alpha1.DefaultMaxTokenExpiration}
	}
	fs.StringArrayVar(&o.OIDCConfig.Audiences, "oidc-audiences", []string{configv1alpha1.DefaultAudience}, "List of audience identifiers used in OIDC resources for trusted shoots.")
	fs.DurationVar(&o.OIDCConfig.MaxTokenExpiration.Duration, "oidc-max-token-expiration", configv1alpha1.DefaultMaxTokenExpiration, "Maximum validity duration of a token.")
}

// Complete implements Completer.Complete.
func (o *TrustConfiguratorOptions) Complete() error {
	if err := o.ControllerOptions.Complete(); err != nil {
		return err
	}
	oidcConfig := o.OIDCConfig
	if o.OIDCConfig.MaxTokenExpiration != nil {
		maxTokenExpiration := *o.OIDCConfig.MaxTokenExpiration
		oidcConfig.MaxTokenExpiration = &maxTokenExpiration
	}

	o.config = &TrustConfiguratorConfig{
		ControllerConfig: o.ControllerOptions.Completed(),
		OIDCConfig:       oidcConfig,
	}
	return nil
}

// Completed returns the completed Config. Only call this if Complete was successful.
func (o *TrustConfiguratorOptions) Completed() *TrustConfiguratorConfig {
	return o.config
}

// TrustConfiguratorConfig is the configuration.
type TrustConfiguratorConfig struct {
	// ControllerConfig holds the completed generic controller configuration.
	ControllerConfig *controllercmd.ControllerConfig
	// OIDCConfig is the OIDC configuration for the trust configurator.
	OIDCConfig configv1alpha1.OIDCConfig
}

// Apply sets the values of this Config in the given trustconfigurator.AddOptions.
func (c *TrustConfiguratorConfig) Apply(opts *trustconfigurator.AddOptions) {
	c.ControllerConfig.Apply(&opts.ControllerOptions)
	opts.OIDCConfig = c.OIDCConfig
}

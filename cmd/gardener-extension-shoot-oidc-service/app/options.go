// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"

	trustconfigv1alpha1 "github.com/gardener/garden-shoot-trust-configurator/pkg/apis/config/v1alpha1"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	heartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	oidccmd "github.com/gardener/gardener-extension-shoot-oidc-service/pkg/cmd"
)

// ExtensionName is the name of the extension.
const ExtensionName = "shoot-oidc-service"

// Options holds configuration passed to the OIDC Service controller.
type Options struct {
	generalOptions           *controllercmd.GeneralOptions
	restOptions              *controllercmd.RESTOptions
	managerOptions           *controllercmd.ManagerOptions
	lifecycleOptions         *controllercmd.ControllerOptions
	controllerSwitches       *controllercmd.SwitchOptions
	reconcileOptions         *controllercmd.ReconcilerOptions
	trustConfiguratorOptions *oidccmd.TrustConfiguratorOptions
	heartbeatOptions         *heartbeatcmd.Options
	webhookOptions           *webhookcmd.AddToManagerOptions
	optionAggregator         controllercmd.OptionAggregator
}

// NewOptions creates a new Options instance.
func NewOptions() *Options {
	// options for the webhook server
	webhookServerOptions := &webhookcmd.ServerOptions{
		Namespace: os.Getenv("WEBHOOK_CONFIG_NAMESPACE"),
	}

	webhookSwitches := oidccmd.WebhookSwitchOptions()
	webhookOptions := webhookcmd.NewAddToManagerOptions(
		ExtensionName,
		"",
		nil,
		nil,
		webhookServerOptions,
		webhookSwitches,
	)

	options := &Options{
		generalOptions: &controllercmd.GeneralOptions{},
		restOptions:    &controllercmd.RESTOptions{},
		managerOptions: &controllercmd.ManagerOptions{
			// These are default values.
			LeaderElection:          true,
			LeaderElectionID:        controllercmd.LeaderElectionNameID(ExtensionName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
			WebhookServerPort:       443,
			WebhookCertDir:          "/tmp/gardener-extensions-cert",
			MetricsBindAddress:      ":8080",
			HealthBindAddress:       ":8081",
		},
		lifecycleOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		heartbeatOptions: &heartbeatcmd.Options{
			// This is a default value.
			ExtensionName:        ExtensionName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		reconcileOptions: &controllercmd.ReconcilerOptions{},
		trustConfiguratorOptions: &oidccmd.TrustConfiguratorOptions{
			ControllerOptions: controllercmd.ControllerOptions{
				// This is a default value.
				MaxConcurrentReconciles: 5,
			},
			OIDCConfig: trustconfigv1alpha1.OIDCConfig{
				Audiences:          []string{trustconfigv1alpha1.DefaultAudience},
				MaxTokenExpiration: &metav1.Duration{Duration: trustconfigv1alpha1.DefaultMaxTokenExpiration},
			},
		},
		controllerSwitches: oidccmd.ControllerSwitches(),
		webhookOptions:     webhookOptions,
	}

	options.optionAggregator = controllercmd.NewOptionAggregator(
		options.generalOptions,
		options.restOptions,
		options.managerOptions,
		controllercmd.PrefixOption("lifecycle-", options.lifecycleOptions),
		controllercmd.PrefixOption("heartbeat-", options.heartbeatOptions),
		controllercmd.PrefixOption("trust-configurator-", options.trustConfiguratorOptions),
		options.controllerSwitches,
		options.reconcileOptions,
		options.webhookOptions,
	)

	return options
}

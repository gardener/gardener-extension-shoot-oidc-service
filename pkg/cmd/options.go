// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/gardener/gardener/extensions/pkg/controller/cmd"
	extensionsheartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/controller/lifecycle"
	webhook "github.com/gardener/gardener-extension-shoot-oidc-service/pkg/webhook/kapiserver"
)

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the oidc webhooks.
func WebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch(webhook.Name, webhook.New),
	)
}

// ControllerSwitches are the cmd.ControllerSwitches for the extension controllers.
func ControllerSwitches() *cmd.SwitchOptions {
	return cmd.NewSwitchOptions(
		cmd.Switch(lifecycle.Name, lifecycle.AddToManager),
		cmd.Switch(extensionsheartbeatcontroller.ControllerName, extensionsheartbeatcontroller.AddToManager),
	)
}

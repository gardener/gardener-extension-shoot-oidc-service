// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

//go:generate sh -c "bash $GARDENER_HACK_DIR/generate-controller-registration.sh shoot-oidc-service . $(cat ../../VERSION) ../../example/controller-registration.yaml Extension:shoot-oidc-service"
//go:generate sh -c "sed -i 's/ type: shoot-oidc-service/ type: shoot-oidc-service\\n    workerlessSupported: true/' ../../example/controller-registration.yaml"

// Package chart enables go:generate support for generating the correct controller registration.
package chart

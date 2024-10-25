#!/bin/bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o nounset
set -o pipefail

# setup virtual GOPATH
source "$GARDENER_HACK_DIR"/vgopath-setup.sh

CODE_GEN_DIR=$(go list -m -f '{{.Dir}}' k8s.io/code-generator)

source "${CODE_GEN_DIR}/kube_codegen.sh"

rm -f $GOPATH/bin/*-gen

PROJECT_ROOT=$(dirname $0)/..

kube::codegen::gen_helpers \
  --boilerplate "${PROJECT_ROOT}/hack/LICENSE_BOILERPLATE.txt" \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-oidc-service/pkg/apis/config \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-oidc-service/pkg/apis/config/v1alpha1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/apis/meta/v1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/conversion \
  --extra-peer-dir k8s.io/apimachinery/pkg/runtime \
  --extra-peer-dir github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
  "${PROJECT_ROOT}/pkg/apis/config"

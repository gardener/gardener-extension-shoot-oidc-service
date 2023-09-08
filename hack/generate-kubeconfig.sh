#!/bin/bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

namespace="garden-local"
shoot_name="local"

if [[ -n $1 ]] ; then
    namespace=$1
fi

if [[ -n $2 ]] ; then
    shoot_name=$1
fi

kubectl create \
    -f "$(dirname "${0}")"/kubeconfig-request.json \
    --raw /apis/core.gardener.cloud/v1beta1/namespaces/"${namespace}"/shoots/"${shoot_name}"/adminkubeconfig | jq -r ".status.kubeconfig" | base64 -d

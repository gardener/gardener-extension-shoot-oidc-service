#!/bin/bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o nounset
set -o pipefail
set -o errexit

repo_root="$(readlink -f $(dirname ${0})/..)"

version=$(git rev-parse HEAD)-$RANDOM
docker build --tag shoot-oidc-service-local:$version $repo_root
kind load docker-image shoot-oidc-service-local:$version --name gardener-local

mkdir -p $repo_root/tmp
cp -f $repo_root/example/controller-registration.yaml $repo_root/tmp/controller-registration.yaml
yq -i e "(select (.helm.values.image) | .helm.values.image.tag) |= \"$version\"" $repo_root/tmp/controller-registration.yaml
yq -i e '(select (.helm.values.image) | .helm.values.image.repository) |= "docker.io/library/shoot-oidc-service-local"' $repo_root/tmp/controller-registration.yaml

# --server-side apply is a workaround for https://github.com/gardener/gardener/issues/10267.
# kubectl apply attempts a strategic merge patch which fails for a ControllerDeployment.
# For more details, see https://github.com/gardener/gardener/issues/10267.
#
# TODO: Remove `--server-side` and `--force-conflicts` flags when the above issue is resolved.
kubectl apply -f "$repo_root/tmp/controller-registration.yaml" \
    --server-side \
    --force-conflicts

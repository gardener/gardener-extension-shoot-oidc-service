#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o nounset
set -o pipefail
set -o errexit

# If running in prow, we need to ensure that registry.local.gardener.cloud resolves to localhost
ensure_glgc_resolves_to_localhost() {
  if [ -n "${CI:-}" ]; then
    # <<< TODO(vpnachev): Remove after github.com/gardener/gardener v1.137.0 has been released.
    printf "\n127.0.0.1 garden.local.gardener.cloud\n" >> /etc/hosts
    printf "\n::1 garden.local.gardener.cloud\n" >> /etc/hosts
    # >>>
    printf "\n127.0.0.1 registry.local.gardener.cloud\n" >> /etc/hosts
    printf "\n::1 registry.local.gardener.cloud\n" >> /etc/hosts
  fi
}

repo_root="$(readlink -f $(dirname ${0})/..)"
gardener_version=$(go list -m -f '{{.Version}}' github.com/gardener/gardener)

if [[ ! -d "$repo_root/gardener" ]]; then
  git clone https://github.com/gardener/gardener.git
  cd "$repo_root/gardener"
else
  cd "$repo_root/gardener"
  git fetch
fi

ensure_glgc_resolves_to_localhost

git checkout "$gardener_version"
make kind-up
export KUBECONFIG=$repo_root/gardener/example/gardener-local/kind/local/kubeconfig
make gardener-up

cd $repo_root

version=$(git rev-parse HEAD)
docker build --tag shoot-oidc-service-local:$version $repo_root
kind load docker-image shoot-oidc-service-local:$version --name gardener-local

mkdir -p $repo_root/tmp
cp -f $repo_root/example/controller-registration.yaml $repo_root/tmp/controller-registration.yaml
yq -i e "(select (.helm.values.image) | .helm.values.image.tag) |= \"$version\"" $repo_root/tmp/controller-registration.yaml
yq -i e '(select (.helm.values.image) | .helm.values.image.repository) |= "docker.io/library/shoot-oidc-service-local"' $repo_root/tmp/controller-registration.yaml

kubectl apply -f "$repo_root/tmp/controller-registration.yaml"

# reduce flakiness in contended pipelines
export GOMEGA_DEFAULT_EVENTUALLY_TIMEOUT=5s
export GOMEGA_DEFAULT_EVENTUALLY_POLLING_INTERVAL=200ms
# if we're running low on resources, it might take longer for tested code to do something "wrong"
# poll for 5s to make sure, we're not missing any wrong action
export GOMEGA_DEFAULT_CONSISTENTLY_DURATION=5s
export GOMEGA_DEFAULT_CONSISTENTLY_POLLING_INTERVAL=200ms

ginkgo --timeout=1h --v --progress "$@" $repo_root/test/e2e/...

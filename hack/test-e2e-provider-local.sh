#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o nounset
set -o pipefail
set -o errexit

repoRoot="$(readlink -f $(dirname ${0})/..)"

if [[ ! -d "$repoRoot/gardener" ]]; then
  git clone https://github.com/gardener/gardener.git
fi

cd "$repoRoot/gardener"
make kind-up
export KUBECONFIG=$repoRoot/gardener/example/provider-local/base/kubeconfig
make gardener-up

cd $repoRoot

version=$(git rev-parse HEAD)
docker build --tag shoot-oidc-service-local:$version $repoRoot
kind load docker-image shoot-oidc-service-local:$version --name gardener-local

mkdir -p $repoRoot/tmp
cp -f $repoRoot/example/controller-registration.yaml $repoRoot/tmp/controller-registration.yaml
yq -i e "(select (.providerConfig.values.image) | .providerConfig.values.image.tag) |= \"$version\"" $repoRoot/tmp/controller-registration.yaml
yq -i e '(select (.providerConfig.values.image) | .providerConfig.values.image.repository) |= "docker.io/library/shoot-oidc-service-local"' $repoRoot/tmp/controller-registration.yaml

kubectl apply -f "$repoRoot/tmp/controller-registration.yaml"

kubectl apply -f "$repoRoot/test/resources/shoot.yaml"

go test -timeout=30m -mod=vendor "$repoRoot/test/system/lifecycle" \
  --v -ginkgo.v -ginkgo.progress \
  --shoot-name=local \
  --project-namespace=garden-local \
  --kubecfg="$KUBECONFIG"

kubectl -n garden-local annotate shoot "local" confirmation.gardener.cloud/deletion=true
kubectl -n garden-local delete shoot "local"

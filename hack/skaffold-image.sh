# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# See skaffold-imagevector.sh for documentation

set -o pipefail
set -o errexit

image_repo=$(echo $SKAFFOLD_IMAGE | cut -d':' -f1,2)
image_tag=$(echo $SKAFFOLD_IMAGE | cut -d':' -f3)

cat <<EOF > local-setup/patch-image.yaml
apiVersion: core.gardener.cloud/v1
kind: ControllerDeployment
metadata:
  name: shoot-oidc-service
helm:
  values:
    image:
      repository: ${image_repo}
      tag: ${image_tag}
EOF

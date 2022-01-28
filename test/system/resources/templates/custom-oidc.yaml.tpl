# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

apiVersion: authentication.gardener.cloud/v1alpha1
kind: OpenIDConnect
metadata:
  name: custom
spec:
  issuerURL: {{ .issuerURL }}
  clientID: {{ .clientID }}
  usernameClaim: sub
  usernamePrefix: "custom-prefix:"
  jwks:
    keys: {{ .keys }}

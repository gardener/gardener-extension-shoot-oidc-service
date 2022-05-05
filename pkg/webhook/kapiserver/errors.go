// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import "fmt"

type NoCASecretError struct{}

func (e *NoCASecretError) Error() string {
	return "CA bundle secret is yet not available"
}

type NoIssuedAtTimeError struct {
	secretName string
	namespace  string
}

func (e *NoIssuedAtTimeError) Error() string {
	return fmt.Sprintf("CA bundle secret %s in namsepace %s has no \"issued-at-time\" label", e.secretName, e.namespace)
}

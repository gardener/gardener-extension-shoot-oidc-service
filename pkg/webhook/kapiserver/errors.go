// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"fmt"
)

type noCASecretError struct{}

func (e *noCASecretError) Error() string {
	return "CA bundle secret is yet not available"
}

type noIssuedAtTimeError struct {
	secretName string
	namespace  string
}

func (e *noIssuedAtTimeError) Error() string {
	return fmt.Sprintf("CA bundle secret %s in namespace %s has no \"issued-at-time\" label", e.secretName, e.namespace)
}

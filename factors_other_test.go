// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package factors

import (
	"context"
	"errors"
	"testing"

	"github.com/go-authn/mfa"
)

// TestOffMacOSBothFactorsAreAbsentRatherThanRefusing. A Linux machine has not
// failed anyone's Touch ID; it has no Touch ID. Reporting a refusal would tell
// a person to try harder at something that does not exist.
func TestOffMacOSBothFactorsAreAbsentRatherThanRefusing(t *testing.T) {
	for _, f := range []mfa.Factor{
		TouchID("unlock"),
		SecurityKey("example.test", nil),
	} {
		err := f.Verify(context.Background())
		if err == nil {
			t.Fatalf("%s succeeded off macOS", f.Name())
		}
		if !errors.Is(err, mfa.ErrUnavailable) {
			t.Errorf("%s = %v, want it to read as unavailable", f.Name(), err)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s lost the reason: %v", f.Name(), err)
		}
	}
}

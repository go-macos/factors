// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package factors

import (
	"context"
	"errors"

	authn "github.com/go-authn/fido"
	"github.com/go-authn/keyfactor"
	"github.com/go-authn/mfa"
	macfido "github.com/go-macos/fido"
	"github.com/go-macos/localauthentication"
)

// platformAskSensor asks LocalAuthentication.
//
// The conditions that mean "there is nothing here to ask" are mapped to
// [mfa.ErrUnavailable] and everything else is a refusal. The distinction is
// the whole reason this function is not one line: a Mac with no sensor, or one
// where nobody has enrolled a finger, has refused nobody, and a policy that
// counted it as a failure would tell a person to try harder at something that
// does not exist.
func platformAskSensor(ctx context.Context, reason string, biometryOnly bool) error {
	policy := localauthentication.PolicyOwner
	if biometryOnly {
		policy = localauthentication.PolicyBiometrics
	}
	if err := localauthentication.Available(policy); err != nil {
		if asUnavailable(err,
			localauthentication.ErrUnavailable,
			localauthentication.ErrBiometryNotAvailable,
			localauthentication.ErrBiometryNotEnrolled,
		) {
			return unavailable(err)
		}
		// A locked-out sensor is NOT unavailable: it is a sensor that has
		// refused too often, which is a real answer and one the person can act
		// on by using their password.
		return err
	}
	return localauthentication.Evaluate(ctx, policy, reason)
}

// platformOpen finds a security key over IOKit.
//
// This is all that is macOS's about the key factor. Everything else -- the
// challenge, the assertion, the flag checks, the refusal to spend somebody's
// last PIN attempt -- is the same everywhere CTAP is and lives in
// github.com/go-authn/keyfactor. It lived HERE first, and was one copy away
// from living in a Linux package too.
func platformOpen(context.Context) (authn.Transport, error) {
	t, err := macfido.Transport()
	if err != nil {
		if errors.Is(err, macfido.ErrNoKey) {
			// An empty USB port has refused nobody.
			return nil, keyfactor.Unavailable(err)
		}
		return nil, err
	}
	return t, nil
}

// compile-time proof that the factors satisfy the interface.
var (
	_ mfa.Factor = touchIDFactor{}
	_ mfa.Factor = refusing{}
)

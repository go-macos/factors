// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package factors

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	authn "github.com/go-authn/fido"
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

// platformAskKey asks a security key for an assertion.
//
// The client data hash is random. Nothing here verifies the signature, so
// there is no protocol to bind to -- and a FIXED hash would let a recorded
// assertion be replayed at this function forever. A caller that needs a
// verifiable assertion should use go-authn/fido directly and check the
// signature; this factor answers the narrower question of whether the key is
// here and somebody touched it.
func platformAskKey(ctx context.Context, f keyFactor) error {
	t, err := macfido.Transport()
	if err != nil {
		if errors.Is(err, macfido.ErrNoKey) {
			return unavailable(err)
		}
		return err
	}
	k, err := authn.Open(ctx, t)
	if err != nil {
		return err
	}
	defer k.Close()

	var hash [sha256.Size]byte
	if _, err := rand.Read(hash[:]); err != nil {
		return fmt.Errorf("factors: cannot make a challenge: %w", err)
	}

	req := authn.GetAssertionRequest{
		RPID:           f.rpID,
		ClientDataHash: hash[:],
		Options:        map[string]bool{"up": true},
	}
	if len(f.credential) > 0 {
		req.Allow = []authn.Credential{{ID: f.credential}}
	}
	if f.verify {
		tok, err := pinToken(ctx, k, f)
		if err != nil {
			return err
		}
		req.Token = tok
		req.Options["uv"] = true
	}
	a, err := k.GetAssertion(ctx, req)
	if err != nil {
		return err
	}
	// The key answering is not enough: it must say a person was there.
	if !a.Parsed.Flags.Has(authn.FlagUP) {
		return fmt.Errorf("factors: %s answered without anyone touching it", f.Name())
	}
	if f.verify && !a.Parsed.Flags.Has(authn.FlagUV) {
		return fmt.Errorf("factors: %s was asked to verify who holds it and did not", f.Name())
	}
	return nil
}

// pinToken buys a token, having first asked how many attempts are left.
//
// Asking first is not politeness. A wrong PIN costs a retry, a key that runs
// out locks until it is unplugged and then permanently, and a factor that
// spent somebody's last attempt on a typo would have destroyed something.
func pinToken(ctx context.Context, k *authn.Key, f keyFactor) (authn.Token, error) {
	r, err := k.PINRetries(ctx)
	if err != nil {
		return authn.Token{}, err
	}
	if r.PowerCycle {
		return authn.Token{}, fmt.Errorf("factors: %s will take no more PINs until it is unplugged", f.Name())
	}
	if r.PIN <= 1 {
		return authn.Token{}, fmt.Errorf(
			"factors: %s has %d attempt(s) left and this one is not being spent on a guess; "+
				"unlock it another way first", f.Name(), r.PIN)
	}
	// Protocol two where the key offers it: it separates the encryption key
	// from the authentication key and uses a fresh initialisation vector.
	proto := authn.PINProtocolOne
	if info, err := k.GetInfo(ctx); err == nil {
		for _, p := range info.PINProtocols {
			if authn.PINProtocol(p) == authn.PINProtocolTwo {
				proto = authn.PINProtocolTwo
			}
		}
	}
	return k.PINToken(ctx, f.pin, proto, authn.PermGetAssertion, f.rpID)
}

// compile-time proof that the factors satisfy the interface.
var (
	_ mfa.Factor = touchIDFactor{}
	_ mfa.Factor = keyFactor{}
)

// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package factors makes macOS's authentication factors usable by
// github.com/go-authn/mfa.
//
// It exists so the bindings do not have to know about policy. A binding's job
// is to reach a framework; deciding how much proof is enough is somebody
// else's, and a low-level package that imported a policy package would drag
// that decision into every program that only wanted Touch ID.
//
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
//	    factors.TouchID("unlock the vault"),
//	    factors.SecurityKey("example.test", credentialID),
//	)
//
// # What each factor actually proves
//
// [TouchID] proves that whoever is at this machine can satisfy the sensor the
// account owner enrolled — something they ARE. [SecurityKey] proves that a
// particular credential is present and that a human touched it — something
// they HAVE. Those are different kinds, which is what lets a policy asking for
// distinct kinds be satisfied by the two together and not by either twice.
//
// # Unavailable is not refused
//
// A Mac with no Touch ID sensor has refused nobody, and neither has an empty
// USB port. Both report [mfa.ErrUnavailable], which a policy counts separately:
// a person can be told to plug their key in, which is not the same as being
// told they failed.
package factors

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-authn/mfa"
)

// touchIDFactor asks the local sensor.
type touchIDFactor struct {
	reason string
	// biometryOnly asks for the sensor and nothing else. False also accepts
	// the login password, which is a different KIND of proof -- something
	// known rather than something one is -- and a factor that silently
	// accepted either would report the wrong kind to a policy.
	biometryOnly bool
}

// TouchID is the sensor as a factor. reason is what macOS shows the person in
// its own prompt, so it should say what is being unlocked.
//
// It asks for BIOMETRY only. The framework can also be asked to accept the
// login password, and this deliberately does not: a factor that answered yes
// to either would be reporting [mfa.Inherence] when what happened was
// [mfa.Knowledge]. Use [DeviceOwner] when either will do, and it says so.
func TouchID(reason string) mfa.Factor {
	return touchIDFactor{reason: reason, biometryOnly: true}
}

// DeviceOwner is the sensor OR the login password, whichever the person
// chooses.
//
// Its kind is [mfa.Unknown], honestly: which one they used is not reported
// back, so this factor cannot say what it proved. A policy asking for distinct
// kinds will therefore never count it towards them -- which is the right
// answer rather than a limitation, because two factors that might both be
// passwords are not two factors.
func DeviceOwner(reason string) mfa.Factor {
	return touchIDFactor{reason: reason}
}

func (f touchIDFactor) Name() string {
	if f.biometryOnly {
		return "Touch ID"
	}
	return "Touch ID or your password"
}

func (f touchIDFactor) Kind() mfa.Kind {
	if f.biometryOnly {
		return mfa.Inherence
	}
	return mfa.Unknown
}

// keyFactor asks a security key.
type keyFactor struct {
	rpID       string
	credential []byte
	// verify demands that the key verify WHO is holding it -- a PIN or its own
	// sensor -- rather than merely that somebody touched it.
	verify bool
	pin    string
}

// SecurityKey is a registered credential as a factor: the key must be present
// and a human must touch it.
//
// credentialID is what a registration returned. Passing none asks the key for
// a discoverable credential, which it has only if one was registered with the
// "rk" option.
//
// This proves POSSESSION and nothing more. A key on a desk that anybody can
// reach is still a key anybody can reach, which is exactly why it belongs
// alongside a factor of another kind rather than alone.
func SecurityKey(rpID string, credentialID []byte) mfa.Factor {
	return keyFactor{rpID: rpID, credential: credentialID}
}

// VerifiedSecurityKey is the same, with the key asked to verify who holds it.
//
// The PIN travels no further than the key: what goes over the wire is the first
// sixteen bytes of its SHA-256, encrypted under a secret agreed for that one
// exchange. It is still a secret in a Go string, so a caller that can avoid
// holding one should.
//
// A wrong PIN costs the key a retry and a key that runs out locks. This asks
// the key how many are left first, and refuses rather than spending the last
// one blindly.
func VerifiedSecurityKey(rpID string, credentialID []byte, pin string) mfa.Factor {
	return keyFactor{rpID: rpID, credential: credentialID, verify: true, pin: pin}
}

func (f keyFactor) Name() string {
	if f.verify {
		return "your security key and its PIN"
	}
	return "your security key"
}

// Kind is possession even when a PIN is involved.
//
// A PIN entered INTO THE KEY is not a factor a policy can count separately: it
// never reaches the platform, it protects the key rather than identifying the
// person to us, and counting it would let one object masquerade as two
// factors. What it changes is the strength of the possession proof, which shows
// up as the verified bit in the assertion, not as a second kind.
func (f keyFactor) Kind() mfa.Kind { return mfa.Possession }

// unavailable wraps err as something a policy treats as "not asked".
func unavailable(err error) error {
	return fmt.Errorf("%w: %w", mfa.ErrUnavailable, err)
}

// asUnavailable reports whether err is one of the "there is nothing here to
// ask" conditions rather than a refusal.
func asUnavailable(err error, sentinels ...error) bool {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// The seams every factor goes through, so a test can drive a sensor that
// refuses, a sensor that is not there, a key that is unplugged and a key whose
// PIN is wrong -- on a machine where all four behave.
var (
	askSensor = platformAskSensor
	askKey    = platformAskKey
)

// Verify asks the sensor.
func (f touchIDFactor) Verify(ctx context.Context) error {
	if f.reason == "" {
		// macOS shows this to the person and refuses an empty one. Failing here
		// rather than there means the error names the programming mistake
		// instead of the framework's complaint about it.
		return fmt.Errorf("factors: a Touch ID prompt needs a reason to show the person")
	}
	return askSensor(ctx, f.reason, f.biometryOnly)
}

// Verify asks the key.
func (f keyFactor) Verify(ctx context.Context) error {
	if f.rpID == "" {
		return fmt.Errorf("factors: a security key needs a relying party id to assert for")
	}
	if f.verify && f.pin == "" {
		return fmt.Errorf("factors: %s was asked to verify without a PIN", f.Name())
	}
	return askKey(ctx, f)
}

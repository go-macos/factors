// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"context"
	"errors"
	"strings"
	"testing"

	fido "github.com/go-authn/fido"
	"github.com/go-authn/mfa"
)

// errNoKeyHere is what a fake opener reports.
//
// Whether a key that ANSWERS satisfies the factor is
// github.com/go-authn/keyfactor's question, and it is tested there against a
// fake authenticator. What is left here is what macOS owns: finding the key,
// and what its absence means.
var errNoKeyHere = errors.New("no security key is attached")

// swap installs fake platform answers and puts the real ones back.
func swap(t *testing.T, sensor func(context.Context, string, bool) error, key func(context.Context) (fido.Transport, error)) {
	t.Helper()
	oldSensor, oldOpen := askSensor, open
	t.Cleanup(func() { askSensor, open = oldSensor, oldOpen })
	if sensor != nil {
		askSensor = sensor
	}
	if key != nil {
		open = key
	}
}

// TestTheTwoFactorsAreOfDifferentKinds is what makes them usable together: a
// policy asking for distinct kinds is satisfied by the pair and by neither
// twice.
func TestTheTwoFactorsAreOfDifferentKinds(t *testing.T) {
	touch := TouchID("unlock the vault")
	key := SecurityKey("example.test", []byte("cred"))
	if touch.Kind() != mfa.Inherence {
		t.Errorf("Touch ID is %v, want inherence", touch.Kind())
	}
	if key.Kind() != mfa.Possession {
		t.Errorf("a security key is %v, want possession", key.Kind())
	}
	if touch.Kind() == key.Kind() {
		t.Fatal("the two factors are the same kind, so the pair is not two factors")
	}
	// And two keys never satisfy a two-KIND policy, whatever they answer.
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true},
		SecurityKey("example.test", []byte("a")), SecurityKey("example.test", []byte("b")),
	); err == nil {
		t.Error("two security keys satisfied a two-KIND policy")
	}
}

// TestAPINIsNotASecondFactor. A PIN entered into the key never reaches the
// platform, and counting it would let one object masquerade as two factors.
func TestAPINIsNotASecondFactor(t *testing.T) {
	if got := VerifiedSecurityKey("example.test", []byte("c"), "0000").Kind(); got != mfa.Possession {
		t.Errorf("a key with a PIN is %v, want possession", got)
	}
}

// TestDeviceOwnerWillNotClaimAKind: it accepts the sensor OR the password and
// is not told which, so it cannot say what it proved.
func TestDeviceOwnerWillNotClaimAKind(t *testing.T) {
	f := DeviceOwner("unlock the vault")
	if f.Kind() != mfa.Unknown {
		t.Errorf("DeviceOwner claims %v; it cannot know", f.Kind())
	}
	if !strings.Contains(f.Name(), "password") {
		t.Errorf("Name() = %q, which does not warn that a password will do", f.Name())
	}
	// So it never counts towards distinct kinds, even paired with a key.
	swap(t, func(context.Context, string, bool) error { return nil }, nil)
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true}, f, SecurityKey("example.test", nil),
	); err == nil {
		t.Error("an unclassified factor was counted towards a kind")
	}
}

// TestNothingHereToAskIsNotAFailure. A Mac with no sensor and an empty USB
// port have refused nobody.
func TestNothingHereToAskIsNotAFailure(t *testing.T) {
	swap(t,
		func(context.Context, string, bool) error { return unavailable(errors.New("no sensor")) },
		func(context.Context) (fido.Transport, error) { return nil, unavailable(errNoKeyHere) })

	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1},
		TouchID("unlock"), SecurityKey("example.test", nil))
	if err == nil {
		t.Fatal("a machine with neither factor satisfied a policy")
	}
	for _, a := range r.Answers {
		if !a.Unavailable() {
			t.Errorf("%s was reported as a refusal rather than as absent", a.Name)
		}
	}
}

// TestARefusalIsARefusal, and an ordinary failure from the opener is one:
// only the conditions this package NAMES are excused.
func TestARefusalIsARefusal(t *testing.T) {
	swap(t,
		func(context.Context, string, bool) error { return errors.New("the finger did not match") },
		func(context.Context) (fido.Transport, error) { return nil, errors.New("the bus caught fire") })

	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1},
		TouchID("unlock"), SecurityKey("example.test", nil))
	if err == nil {
		t.Fatal("two refusals satisfied a policy")
	}
	for _, a := range r.Answers {
		if a.Unavailable() {
			t.Errorf("%s was reported as absent rather than as refusing", a.Name)
		}
	}
	if !strings.Contains(err.Error(), "did not match") {
		t.Errorf("the error says %q, which does not name what refused", err)
	}
}

// TestAVerifiedKeyWithNoPINIsAMistake, not a weaker factor.
//
// Quietly returning an unverified key would hand a caller less proof than they
// asked for and never say so. The check has nowhere to live but Verify, since
// mfa.Factor has no way to fail at construction.
func TestAVerifiedKeyWithNoPINIsAMistake(t *testing.T) {
	reached := 0
	swap(t, nil, func(context.Context) (fido.Transport, error) {
		reached++
		return nil, errNoKeyHere
	})
	f := VerifiedSecurityKey("example.test", nil, "")
	err := f.Verify(context.Background())
	if err == nil {
		t.Fatal("a verified key with no PIN was accepted")
	}
	if !strings.Contains(err.Error(), "without a PIN") {
		t.Errorf("error = %q", err)
	}
	if reached != 0 {
		t.Errorf("the key was opened %d time(s) for a request that could not be honoured", reached)
	}
	// It still classifies, so a policy's report reads sensibly.
	if f.Kind() != mfa.Possession || !strings.Contains(f.Name(), "PIN") {
		t.Errorf("%s is %v", f.Name(), f.Kind())
	}
}

func TestAFactorRefusesAnIncompleteRequest(t *testing.T) {
	asked := 0
	swap(t, func(context.Context, string, bool) error { asked++; return nil },
		func(context.Context) (fido.Transport, error) { asked++; return nil, errNoKeyHere })

	for _, c := range []struct {
		name string
		f    mfa.Factor
		want string
	}{
		{"a prompt with no reason", TouchID(""), "needs a reason"},
		{"a key with no relying party", SecurityKey("", nil), "relying party id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.Verify(context.Background())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
	if asked != 0 {
		t.Errorf("the platform was asked %d time(s) for an incomplete request", asked)
	}
}

// TestTheOpenerIsReached, so the delegation is wired rather than merely
// compiled.
func TestTheOpenerIsReached(t *testing.T) {
	reached := 0
	swap(t, nil, func(context.Context) (fido.Transport, error) {
		reached++
		return nil, errNoKeyHere
	})
	if err := SecurityKey("example.test", []byte("c")).Verify(context.Background()); err == nil {
		t.Fatal("a factor with no key behind it succeeded")
	}
	if reached != 1 {
		t.Errorf("the opener was reached %d times", reached)
	}
}

func TestTheFactorsSayWhatTheyAre(t *testing.T) {
	for _, c := range []struct {
		f    mfa.Factor
		want string
	}{
		{TouchID("x"), "Touch ID"},
		{SecurityKey("a", nil), "security key"},
		{VerifiedSecurityKey("a", nil, "0000"), "PIN"},
	} {
		if !strings.Contains(c.f.Name(), c.want) {
			t.Errorf("Name() = %q, want it to mention %q", c.f.Name(), c.want)
		}
	}
}

// TestBiometryOnlyIsAskedFor: the framework can also accept the login
// password, and TouchID deliberately does not, because a factor that answered
// yes to either would report inherence when what happened was knowledge.
func TestBiometryOnlyIsAskedFor(t *testing.T) {
	var sawBiometryOnly []bool
	swap(t, func(_ context.Context, _ string, only bool) error {
		sawBiometryOnly = append(sawBiometryOnly, only)
		return nil
	}, nil)
	if err := TouchID("unlock").Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := DeviceOwner("unlock").Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sawBiometryOnly) != 2 || !sawBiometryOnly[0] || sawBiometryOnly[1] {
		t.Errorf("biometry-only was asked as %v, want [true false]", sawBiometryOnly)
	}
}

func TestUnavailableWrapsBothWays(t *testing.T) {
	inner := errors.New("no sensor")
	err := unavailable(inner)
	if !errors.Is(err, mfa.ErrUnavailable) {
		t.Error("the wrapper is not recognisable as unavailable")
	}
	if !errors.Is(err, inner) {
		t.Error("the wrapper lost the reason")
	}
	if asUnavailable(inner, errors.New("something else")) {
		t.Error("asUnavailable matched an unrelated error")
	}
	if !asUnavailable(err, mfa.ErrUnavailable) {
		t.Error("asUnavailable did not match its own sentinel")
	}
}

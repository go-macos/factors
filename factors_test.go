// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package factors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/mfa"
)

// swap installs fake platform answers and puts the real ones back.
func swap(t *testing.T, sensor func(context.Context, string, bool) error, key func(context.Context, keyFactor) error) {
	t.Helper()
	os_, ok := askSensor, askKey
	t.Cleanup(func() { askSensor, askKey = os_, ok })
	if sensor != nil {
		askSensor = sensor
	}
	if key != nil {
		askKey = key
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

	swap(t, func(context.Context, string, bool) error { return nil },
		func(context.Context, keyFactor) error { return nil })
	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 2, DistinctKinds: true}, touch, key)
	if err != nil {
		t.Fatalf("the pair did not satisfy a two-kind policy: %v", err)
	}
	if r.Kinds != 2 {
		t.Errorf("%d kinds among the pair", r.Kinds)
	}
	// And neither twice does.
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true},
		SecurityKey("example.test", []byte("a")), SecurityKey("example.test", []byte("b")),
	); err == nil {
		t.Error("two security keys satisfied a two-KIND policy")
	}
}

// TestAPINIsNotASecondFactor. A PIN entered into the key never reaches the
// platform and protects the key rather than identifying the person to us;
// counting it separately would let one object masquerade as two factors.
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
	swap(t, func(context.Context, string, bool) error { return nil },
		func(context.Context, keyFactor) error { return nil })
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2, DistinctKinds: true}, f, SecurityKey("example.test", nil),
	); err == nil {
		t.Error("an unclassified factor was counted towards a kind")
	}
	// It does satisfy a plain count, which is a different request.
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 2}, f, SecurityKey("example.test", nil)); err != nil {
		t.Errorf("a plain count of two refused two answers: %v", err)
	}
}

// TestNothingHereToAskIsNotAFailure. A Mac with no sensor and an empty USB
// port have refused nobody.
func TestNothingHereToAskIsNotAFailure(t *testing.T) {
	swap(t,
		func(context.Context, string, bool) error { return unavailable(errors.New("no sensor")) },
		func(context.Context, keyFactor) error { return unavailable(errors.New("no key")) })

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
	// Even with StopOnFirstFailure, an absent factor does not end the attempt:
	// nothing refused.
	swap(t, nil, func(context.Context, keyFactor) error { return nil })
	if _, err := mfa.Verify(context.Background(),
		mfa.Policy{Count: 1, StopOnFirstFailure: true},
		TouchID("unlock"), SecurityKey("example.test", nil)); err != nil {
		t.Errorf("an absent sensor ended the attempt: %v", err)
	}
}

func TestARefusalIsARefusal(t *testing.T) {
	swap(t, func(context.Context, string, bool) error { return errors.New("the finger did not match") },
		func(context.Context, keyFactor) error { return errors.New("nobody touched it") })
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

func TestAFactorRefusesAnIncompleteRequest(t *testing.T) {
	asked := 0
	swap(t, func(context.Context, string, bool) error { asked++; return nil },
		func(context.Context, keyFactor) error { asked++; return nil })

	for _, c := range []struct {
		name string
		f    mfa.Factor
		want string
	}{
		{"a prompt with no reason", TouchID(""), "needs a reason"},
		{"a key with no relying party", SecurityKey("", nil), "relying party id"},
		{"verification with no PIN", VerifiedSecurityKey("example.test", nil, ""), "without a PIN"},
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

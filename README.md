# factors

[![Go Reference](https://pkg.go.dev/badge/github.com/go-macos/factors.svg)](https://pkg.go.dev/github.com/go-macos/factors)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-macos/factors/actions/workflows/ci.yml/badge.svg)](https://github.com/go-macos/factors/actions/workflows/ci.yml)

macOS's authentication factors, as factors —
[`mfa.Factor`](https://github.com/go-authn/mfa) values a policy can ask.
Pure Go, `CGO_ENABLED=0`.

```go
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
    factors.TouchID("unlock the vault"),          // something you are
    factors.SecurityKey("example.test", credID),  // something you have
)
if err != nil {
    fmt.Println(err)  // "2 factor(s) needed, 1 answered: your security key: not plugged in"
}
```

## Why this is a separate package

Nothing in [go-macos/localauthentication](https://github.com/go-macos/localauthentication)
or [go-authn/fido](https://github.com/go-authn/fido) should know what a policy
is. A binding's job is to reach a framework. If either imported a policy
package, that decision would be dragged into every program that only wanted to
show a Touch ID prompt.

So the adapters live here, above both, and the layering is: bindings reach
hardware, `go-authn/mfa` decides, this package is the four lines in between.

## The distinctions it refuses to blur

**Touch ID is not "Touch ID or your password".** The framework will happily
accept either, and a factor that did would report `Inherence` when what
happened was `Knowledge` — a password dressed up as a fingerprint. `TouchID`
asks for biometry only. `DeviceOwner` accepts either and returns
`mfa.Unknown`, so a two-*kind* policy never counts it. Being honest about not
knowing is what stops one factor from passing for two.

**A key's PIN is not a second factor.** It never reaches the platform, and it
protects the key rather than identifying anyone to us. `VerifiedSecurityKey`
is still `Possession`; what the PIN changes is the strength of that one proof,
which shows up as the verified bit in the assertion. Counting it separately
would let a single object masquerade as two factors, which is the exact
failure two-factor authentication exists to prevent.

**Nothing here to ask is not a refusal.** A Mac with no sensor, an empty USB
port, and Linux all report `mfa.ErrUnavailable`, which a policy tallies
separately. Only three LocalAuthentication conditions get that treatment; a
sensor that is *locked out* is a real answer — it has refused too often — and
is reported as one, because the person can act on it by using their password.

**A wrong PIN costs the key an attempt, and the last one is not spent on a
guess.** `pinToken` asks how many are left first and refuses at one, or when
the key says it will take no more until it is unplugged. A key that runs out
locks permanently, taking every credential on it.

**The challenge is random.** This factor does not verify the signature, so
there is no protocol to bind a challenge to — and a fixed one would let a
recorded assertion be replayed here forever. A caller who needs a *verifiable*
assertion should use `go-authn/fido` directly.

## Coverage

Everything portable is covered to 100%, on Linux, with no hardware: the
classification, the kinds, the incomplete-request refusals, and the
absent-versus-refused split all go through the `askSensor`/`askKey` seams.

The three platform functions are not covered, and the gate says so rather than
pretending otherwise. They reach a fingerprint sensor and a plugged-in key; a
test that popped a biometric prompt would be a test nobody could run twice, and
a runner has neither device. They have been exercised by hand against a real
YubiKey FIDO 5.7.4.

The verified path — `VerifiedSecurityKey`, `uv`, `pinToken` — is **not yet
proven on hardware**. Doing that means setting a PIN on a key, and a PIN cannot
be removed afterwards except by `authenticatorReset`, which erases every
credential on it. That waits for a key kept for development.

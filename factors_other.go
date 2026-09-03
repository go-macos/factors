// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package factors

import (
	"context"
	"errors"
)

// ErrUnsupported is what both factors report off macOS. It is wrapped as
// unavailable rather than as a refusal: a Linux machine has not failed anyone's
// Touch ID, it has no Touch ID.
var ErrUnsupported = errors.New("factors: these are macOS factors")

func platformAskSensor(context.Context, string, bool) error { return unavailable(ErrUnsupported) }
func platformAskKey(context.Context, keyFactor) error       { return unavailable(ErrUnsupported) }

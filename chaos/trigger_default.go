// FILE PATH: chaos/trigger_default.go
//
// Default (non-chaos) build of the Trigger function. Compiled
// into the production binary; every call site is dead-code-
// eliminated by the Go toolchain.

//go:build !chaos
// +build !chaos

package chaos

// Trigger is a no-op in production builds. The compiler inlines
// + eliminates each call site. Build with `-tags=chaos` to get
// the panic-on-match behaviour from trigger_chaos.go.
//
// Naming convention: snake_case, stable across versions. The
// name is part of the chaos contract — see trigger.go's
// INJECTION POINTS REGISTERED list.
func Trigger(name string) {}

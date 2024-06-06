//go:build !wasi && !wasip1
// +build !wasi,!wasip1

package capabilities

// NewHost creates a dummy host.
// This is useful when running the policy in a test environment.
func NewHost() Host {
	return Host{}
}

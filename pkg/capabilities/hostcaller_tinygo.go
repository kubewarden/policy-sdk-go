//go:build wasi && !wasip1
// +build wasi,!wasip1

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package capabilities

import (
	wapc "github.com/wapc/wapc-guest-tinygo"
)

type realWapcClient struct {
}

func (c *realWapcClient) HostCall(binding, namespace, operation string, payload []byte) (response []byte, err error) {
	return wapc.HostCall(binding, namespace, operation, payload)
}

// NewHost creates a Host that has a real waPC client.
func NewHost() Host {
	return Host{
		Client: &realWapcClient{},
	}
}

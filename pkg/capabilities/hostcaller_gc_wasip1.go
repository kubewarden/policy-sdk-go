//go:build wasip1 && !tinygo
// +build wasip1,!tinygo

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package capabilities

import (
	"errors"
	"io"
	"os"
	"reflect"
	"unsafe"
)

//go:wasmimport host call
//go:noescape
func hostCall(
	bindingPtr uint32, bindingLen uint32,
	namespacePtr uint32, namespaceLen uint32,
	operationPtr uint32, operationLen uint32,
	payloadPtr uint32, payloadLen uint32) uint32

//go:inline
func bytesToPointer(s []byte) uint32 {
	return uint32((*(*reflect.SliceHeader)(unsafe.Pointer(&s))).Data)
}

//go:inline
func stringToPointer(s string) uint32 {
	return uint32((*(*reflect.StringHeader)(unsafe.Pointer(&s))).Data)
}

type wasiClient struct {
}

func (c *wasiClient) HostCall(binding, namespace, operation string, payload []byte) (response []byte, err error) {
	// HostCall invokes an operation on the host.  The host uses `namespace` and `operation`
	// to route to the `payload` to the appropriate operation.  The host will return
	// `0` if everything went fine, `1` if there was an error.
	successful := hostCall(
		stringToPointer(binding), uint32(len(binding)),
		stringToPointer(namespace), uint32(len(namespace)),
		stringToPointer(operation), uint32(len(operation)),
		bytesToPointer(payload), uint32(len(payload)),
	) == 0

	response, err = io.ReadAll(os.Stdin)
	if err != nil {
		return []byte{}, err
	}

	if successful {
		return response, nil
	}

	return []byte{}, errors.New(string(response))
}

// NewHost creates a Host that can interact with a policy-evaluator host.
func NewHost() Host {
	return Host{
		Client: &wasiClient{},
	}
}

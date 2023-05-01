// This package provides access to the structs and functions offered by the Kubewarden host.
// This allows policies to perform operations that are not doable inside of the WebAssembly
// runtime. Such as, policy verification, reverse DNS lookups, interacting with OCI registries,...
package capabilities

// Host makes possible to interact with the policy host from inside of a
// policy.
//
// Use the `NewHost` function to create an instance of `Host`.
type Host struct {
	Client WapcClient
}

type WapcClient interface {
	HostCall(binding, namespace, operation string, payload []byte) (response []byte, err error)
}

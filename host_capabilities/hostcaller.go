// This package provides access to the structs and functions offered by the Kubewarden host.
// This allows policies to perform operations that are not doable inside of the WebAssembly
// runtime. Such as, policy verification, reverse DNS lookups, interacting with OCI registries,...
package host_capabilities

type HostCaller interface {

	// GetOCIManifest computes the digest of the OCI object referenced by image
	GetOCIManifest(image string) (digest string, err error)

	// LookupHost looks up the addresses for a given hostname via DNS
	LookupHost(host string) (listIPs []string, err error)

	// VerifyPubKeys verifies sigstore signatures of an image using public keys
	// Arguments
	// * image: image to be verified
	// * pubKeys: list of PEM encoded keys that must have been used to sign the OCI object
	// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
	VerifyPubKeys(image string, pubKeys []string, annotations map[string]string) (VerificationResponse, error)

	// VerifyKeyless verifies sigstore signatures of an image using keyless signing
	// Arguments
	// * image: image to be verified
	// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
	// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
	VerifyKeyless(image string, keyless []KeylessInfo, annotations map[string]string) (VerificationResponse, error)
}

type KeylessInfo struct {
	// Issuer is identifier of the OIDC provider. E.g: https://github.com/login/oauth
	Issuer string `json:"issuer"`
	// Subject contains the information of the user used to authenticate against
	// the OIDC provider. E.g: mail@example.com
	Subject string `json:"subject"`
}

type VerificationResponse struct {
	// informs if the image was verified or not
	IsTrusted bool `json:"is_trusted"`
	// digest of the verified image
	Digest string `json:"digest"`
}

// sigstorePubKeysVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls
//
// Note: this is not in use for wasi, as we use gjson and sjson
type sigstorePubKeysVerify struct {
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	PubKeys []string `json:"pub_keys"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// sigstoreKeylessVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls
//
// Note: this is not in use for wasi, as we use gjson and sjson
type sigstoreKeylessVerify struct {
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	Keyless []KeylessInfo `json:"keyless"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

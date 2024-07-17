package verify_v1

import oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"

// sigstorePubKeysVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls.
type sigstorePubKeysVerify struct {
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	PubKeys []string `json:"pub_keys"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

type sigstorePubKeysVerifyRequest struct {
	SigstorePubKeysVerify sigstorePubKeysVerify `json:"SigstorePubKeyVerify"`
}

// sigstoreKeylessVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls.
type sigstoreKeylessVerify struct {
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	Keyless []oci.KeylessInfo `json:"keyless"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

type sigstoreKeylessVerifyRequest struct {
	SigstoreKeylessVerify sigstoreKeylessVerify `json:"SigstoreKeylessVerify"`
}

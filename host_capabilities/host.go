// This package provides access to the structs and functions offered by the Kubewarden host.
// This allows policies to perform operations that are not doable inside of the WebAssembly
// runtime. Such as, policy verification, reverse DNS lookups, interacting with OCI registries,...
package host_capabilities

import (
	"encoding/json"
	"fmt"

	"github.com/mailru/easyjson"
)

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

// GetOCIManifestDigest computes the digest of the OCI object referenced by image
// Arguments:
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
func (h *Host) GetOCIManifestDigest(image string) (string, error) {
	// build request payload, e.g: `"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"`
	payload, err := json.Marshal(image)
	if err != nil {
		return "", fmt.Errorf("cannot serialize image to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/manifest_digest", payload)
	if err != nil {
		return "", err
	}

	response := OciManifestResponse{}
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		return "", fmt.Errorf("cannot unmarshall response: %w", err)
	}

	return response.Digest, nil
}

// LookupHost looks up the addresses for a given hostname via DNS
func (h *Host) LookupHost(host string) ([]string, error) {
	// build request, e.g: `"localhost"`
	payload, err := json.Marshal(host)
	if err != nil {
		return []string{}, fmt.Errorf("cannot serialize host to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "net", "v1/dns_lookup_host", payload)
	if err != nil {
		return []string{}, err
	}

	response := LookupHostResponse{}
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		return []string{}, fmt.Errorf("cannot unmarshall response: %w", err)
	}

	return response.Ips, nil
}

// VerifyPubKeys verifies sigstore signatures of an image using public keys
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * pubKeys: list of PEM encoded keys that must have been used to sign the OCI object
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyPubKeys(image string, pubKeys []string, annotations map[string]string) (VerificationResponse, error) {
	// failsafe return response
	vr := VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	requestObj := sigstorePubKeysVerify{
		Image:       image,
		PubKeys:     pubKeys,
		Annotations: annotations,
	}
	payload, err := requestObj.MarshalJSON()
	if err != nil {
		return vr, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/verify", payload)
	if err != nil {
		return vr, err
	}

	responseObj := VerificationResponse{}
	if err := easyjson.Unmarshal(responsePayload, &responseObj); err != nil {
		return vr, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	return responseObj, nil
}

// VerifyKeyless verifies sigstore signatures of an image using keyless signing
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyKeyless(image string, keyless []KeylessInfo, annotations map[string]string) (VerificationResponse, error) {
	// failsafe return response
	vr := VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	requestObj := sigstoreKeylessVerify{
		Image:       image,
		Keyless:     keyless,
		Annotations: annotations,
	}
	payload, err := requestObj.MarshalJSON()
	if err != nil {
		return vr, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/verify", payload)
	if err != nil {
		return vr, err
	}

	responseObj := VerificationResponse{}
	if err := easyjson.Unmarshal(responsePayload, &responseObj); err != nil {
		return vr, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	return responseObj, nil
}

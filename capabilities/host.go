// This package provides access to the structs and functions offered by the Kubewarden host.
// This allows policies to perform operations that are not doable inside of the WebAssembly
// runtime. Such as, policy verification, reverse DNS lookups, interacting with OCI registries,...
package capabilities

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

type HostOCIVerifyVersion int64

const (
	V1 HostOCIVerifyVersion = iota
	V2
)

func (s HostOCIVerifyVersion) String() string {
	switch s {
	case V1:
		return "v1/verify"
	case V2:
		return "v2/verify"
	}
	return "unknown"
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
	requestObj := sigstorePubKeysVerifyRequest{
		SigstorePubKeysVerify: sigstorePubKeysVerify{
			Image:       image,
			PubKeys:     pubKeys,
			Annotations: annotations,
		},
	}

	return h.verify(requestObj, V1)
}

// VerifyKeyless verifies sigstore signatures of an image using keyless signing
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyKeyless(image string, keyless []KeylessInfo, annotations map[string]string) (VerificationResponse, error) {
	requestObj := sigstoreKeylessVerifyRequest{
		SigstoreKeylessVerify: sigstoreKeylessVerify{
			Image:       image,
			Keyless:     keyless,
			Annotations: annotations,
		},
	}

	return h.verify(requestObj, V1)
}

// VerifyPubKeysImageV2 verifies sigstore signatures of an image using public keys
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * pubKeys: list of PEM encoded keys that must have been used to sign the OCI object
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyPubKeysImageV2(image string, pubKeys []string, annotations map[string]string) (VerificationResponse, error) {
	requestObj := sigstorePubKeysVerifyV2{
		Image:       image,
		PubKeys:     pubKeys,
		Annotations: annotations,
	}

	return h.verify(requestObj, V2)
}

// VerifyKeylessExactMatchV2 verifies sigstore signatures of an image using keyless signing
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyKeylessExactMatchV2(image string, keyless []KeylessInfo, annotations map[string]string) (VerificationResponse, error) {
	requestObj := sigstoreKeylessVerifyExactV2{
		Image:       image,
		Keyless:     keyless,
		Annotations: annotations,
	}

	return h.verify(requestObj, V2)
}

// verify sigstore signatures of an image using keyless. Here, the provided
// subject string is treated as a URL prefix, and sanitized to a valid URL on
// itself by appending `/` to prevent typosquatting. Then, the provided subject
// will satisfy the signature only if it is a prefix of the signature subject.
// # Arguments
// * `image` -  image to be verified
// * `keyless`  -  list of issuers and subjects
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyKeylessPrefixMatchV2(image string, keylessPrefix []KeylessPrefixInfo, annotations map[string]string) (VerificationResponse, error) {
	requestObj := sigstoreKeylessPrefixVerifyV2{
		Image:         image,
		KeylessPrefix: keylessPrefix,
		Annotations:   annotations,
	}

	return h.verify(requestObj, V2)
}

// verify sigstore signatures of an image using keyless signatures made via
// Github Actions.
// # Arguments
// * `image` -  image to be verified
// * `owner` - owner of the repository. E.g: octocat
// * `repo` - Optional. repo of the GH Action workflow that signed the artifact. E.g: example-repo. Optional.
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyKeylessGithubActionsV2(image string, owner string, repo string, annotations map[string]string) (VerificationResponse, error) {
	requestObj := sigstoreGithubActionsVerifyV2{
		Image:       image,
		Owner:       owner,
		Repo:        repo,
		Annotations: annotations,
	}

	return h.verify(requestObj, V2)
}

// verify sigstore signatures of an image using a user provided certificate
// # Arguments
//   - `image` -  image to be verified
//   - `certificate` - PEM encoded certificate used to verify the signature
//   - `certificate_chain` - Optional. PEM encoded certificates used to verify `certificate`.
//     When not specified, the certificate is assumed to be trusted
//   - `require_rekor_bundle` - require the  signature layer to have a Rekor bundle.
//     Having a Rekor bundle allows further checks to be performed,
//     like ensuring the signature has been produced during the validity
//     time frame of the certificate.
//     It is recommended to set this value to `true` to have a more secure
//     verification process.
//   - `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
func (h *Host) VerifyCertificateV2(image string, certificate string, certificateChain []string, requireRekorBundle bool, annotations map[string]string) (VerificationResponse, error) {
	chain := make([][]rune, len(certificateChain))
	for i, c := range certificateChain {
		chain[i] = []rune(c)
	}

	requestObj := sigstoreCertificateVerifyV2{
		Image:              image,
		Certificate:        []rune(certificate),
		CertificateChain:   chain,
		RequireRekorBundle: requireRekorBundle,
		Annotations:        annotations,
	}

	return h.verify(requestObj, V2)
}

func (h *Host) verify(requestObj easyjson.Marshaler, operation HostOCIVerifyVersion) (VerificationResponse, error) {
	// failsafe return response
	vr := VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	payload, err := easyjson.Marshal(requestObj)
	if err != nil {
		return vr, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", operation.String(), payload)
	if err != nil {
		return vr, err
	}

	responseObj := VerificationResponse{}
	if err := easyjson.Unmarshal(responsePayload, &responseObj); err != nil {
		return vr, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	return responseObj, nil
}

// ListResourcesByNamespace gets all the Kubernetes resources defined inside of
// the given namespace
// Note: cannot be used for cluster-wide resources
func (h *Host) ListResourcesByNamespace(req ListResourcesByNamespaceRequest) ([]byte, error) {
	payload, err := req.MarshalJSON()
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}

// ListResources gets all the Kubernetes resources defined inside of the cluster.
// Note: this has be used for cluster-wide resources
func (h *Host) ListResources(req ListAllResourcesRequest) ([]byte, error) {
	payload, err := req.MarshalJSON()
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "list_all_resources", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}

// GetResource gets a specific Kubernetes resource.
func (h *Host) GetResource(req GetResourceRequest) ([]byte, error) {
	payload, err := req.MarshalJSON()
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "get_resource", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}

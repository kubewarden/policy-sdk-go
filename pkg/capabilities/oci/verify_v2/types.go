package verify_v2

import (
	oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
)

type KeylessPrefixInfo struct {
	// Issuer is identifier of the OIDC provider. E.g: https://github.com/login/oauth
	Issuer string `json:"issuer"`
	// Valid prefix of the Subject field in the signature used to authenticate
	// against the OIDC provider. It forms a valid URL on its own, and will get
	// sanitized by appending `/` to protect against typosquatting
	UrlPrefix string `json:"url_prefix"`
}

// SigstorePubKeysVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls
type SigstorePubKeysVerify struct {
	Type SigstorePubKeyVerifyType `json:"type"`
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	PubKeys []string `json:"pub_keys"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

// SigstoreKeylessVerifyExact represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls
type SigstoreKeylessVerifyExact struct {
	Type SigstoreKeylessVerifyType `json:"type"`
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of PEM encoded keys that must have been used to sign the OCI object
	Keyless []oci.KeylessInfo `json:"keyless"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

// sigstoreKeylessVerify represents the WaPC JSON contract, used for marshalling
// and unmarshalling payloads to wapc host calls
type SigstoreKeylessPrefixVerify struct {
	Type SigstoreKeylessPrefixVerifyType `json:"type"`
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// List of keyless signatures that must be found
	KeylessPrefix []KeylessPrefixInfo `json:"keyless_prefix"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

type SigstoreGithubActionsVerify struct {
	Type SigstoreGithubActionsVerifyType `json:"type"`
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// owner of the repository. E.g: octocat
	Owner string `json:"owner"`
	// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
	Repo string `json:"repo,omitempty"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

type SigstoreCertificateVerify struct {
	Type SigstoreCertificateVerifyType `json:"type"`
	// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
	Image string `json:"image"`
	// PEM encoded certificate used to verify the signature
	Certificate []rune `json:"certificate"`
	// Optional - the certificate chain that is used to verify the provided
	// certificate. When not specified, the certificate is assumed to be trusted
	CertificateChain [][]rune `json:"certificate_chain"`
	// Require the  signature layer to have a Rekor bundle.
	// Having a Rekor bundle allows further checks to be performed,
	// like ensuring the signature has been produced during the validity
	// time frame of the certificate.
	//
	// It is recommended to set this value to `true` to have a more secure
	// verification process.
	RequireRekorBundle bool `json:"require_rekor_bundle"`
	// Annotations that must have been provided by all signers when they signed
	// the OCI artifact. Optional
	Annotations map[string]string `json:"annotations"`
}

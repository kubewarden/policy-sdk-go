package verify_v2

import (
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
	"github.com/mailru/easyjson/jwriter"
)

type SigstorePubKeyVerifyType struct{}

func (e SigstorePubKeyVerifyType) MarshalEasyJSON(w *jwriter.Writer) {
	w.String("SigstorePubKeyVerify")
}

type SigstoreKeylessVerifyType struct{}

func (e SigstoreKeylessVerifyType) MarshalEasyJSON(w *jwriter.Writer) {
	w.String("SigstoreKeylessVerify")
}

type SigstoreKeylessPrefixVerifyType struct{}

func (e SigstoreKeylessPrefixVerifyType) MarshalEasyJSON(w *jwriter.Writer) {
	w.String("SigstoreKeylessPrefixVerify")
}

type SigstoreGithubActionsVerifyType struct{}

func (e SigstoreGithubActionsVerifyType) MarshalEasyJSON(w *jwriter.Writer) {
	w.String("SigstoreGithubActionsVerify")
}

type SigstoreCertificateVerifyType struct{}

func (e SigstoreCertificateVerifyType) MarshalEasyJSON(w *jwriter.Writer) {
	w.String("SigstoreCertificateVerify")
}

// VerifyPubKeysImageV2 verifies sigstore signatures of an image using public keys
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * pubKeys: list of PEM encoded keys that must have been used to sign the OCI object
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func VerifyPubKeysImage(h *cap.Host, image string, pubKeys []string, annotations map[string]string) (oci.VerificationResponse, error) {
	requestObj := sigstorePubKeysVerify{
		Image:       image,
		PubKeys:     pubKeys,
		Annotations: annotations,
	}

	return oci.Verify(h, requestObj, oci.V2)
}

// VerifyKeylessExactMatchV2 verifies sigstore signatures of an image using keyless signing
// Arguments
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact
func VerifyKeylessExactMatch(h *cap.Host, image string, keyless []oci.KeylessInfo, annotations map[string]string) (oci.VerificationResponse, error) {
	requestObj := sigstoreKeylessVerifyExact{
		Image:       image,
		Keyless:     keyless,
		Annotations: annotations,
	}

	return oci.Verify(h, requestObj, oci.V2)
}

// verify sigstore signatures of an image using keyless. Here, the provided
// subject string is treated as a URL prefix, and sanitized to a valid URL on
// itself by appending `/` to prevent typosquatting. Then, the provided subject
// will satisfy the signature only if it is a prefix of the signature subject.
// # Arguments
// * `image` -  image to be verified
// * `keyless`  -  list of issuers and subjects
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
func VerifyKeylessPrefixMatch(h *cap.Host, image string, keylessPrefix []KeylessPrefixInfo, annotations map[string]string) (oci.VerificationResponse, error) {
	requestObj := sigstoreKeylessPrefixVerify{
		Image:         image,
		KeylessPrefix: keylessPrefix,
		Annotations:   annotations,
	}

	return oci.Verify(h, requestObj, oci.V2)
}

// verify sigstore signatures of an image using keyless signatures made via
// Github Actions.
// # Arguments
// * `image` -  image to be verified
// * `owner` - owner of the repository. E.g: octocat
// * `repo` - Optional. repo of the GH Action workflow that signed the artifact. E.g: example-repo. Optional.
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
func VerifyKeylessGithubActions(h *cap.Host, image string, owner string, repo string, annotations map[string]string) (oci.VerificationResponse, error) {
	requestObj := sigstoreGithubActionsVerify{
		Image:       image,
		Owner:       owner,
		Repo:        repo,
		Annotations: annotations,
	}

	return oci.Verify(h, requestObj, oci.V2)
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
func VerifyCertificate(h *cap.Host, image string, certificate []rune, certificateChain [][]rune, requireRekorBundle bool, annotations map[string]string) (oci.VerificationResponse, error) {
	requestObj := sigstoreCertificateVerify{
		Image:              image,
		Certificate:        certificate,
		CertificateChain:   certificateChain,
		RequireRekorBundle: requireRekorBundle,
		Annotations:        annotations,
	}

	return oci.Verify(h, requestObj, oci.V2)
}

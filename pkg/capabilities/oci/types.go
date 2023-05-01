package oci

type VerificationResponse struct {
	// informs if the image was verified or not
	IsTrusted bool `json:"is_trusted"`
	// digest of the verified image
	Digest string `json:"digest"`
}

type KeylessInfo struct {
	// Issuer is identifier of the OIDC provider. E.g: https://github.com/login/oauth
	Issuer string `json:"issuer"`
	// Subject contains the information of the user used to authenticate against
	// the OIDC provider. E.g: mail@example.com
	Subject string `json:"subject"`
}

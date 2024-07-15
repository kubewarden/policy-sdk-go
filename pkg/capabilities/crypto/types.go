package crypto

// A x509 certificate.
type Certificate struct {
	// Which encoding is used by the certificate
	Encoding CertificateEncoding `json:"encoding"`
	// Actual certificate
	Data []rune `json:"data"`
}

// CertificateVerificationRequest holds information about a certificate and
// a chain to validate it with.
type CertificateVerificationRequest struct {
	/// PEM/DER-encoded certificate
	Cert Certificate `json:"cert"`
	// list of PEM/DER-encoded certs, ordered by trust usage (intermediates first, root last)
	// If empty, certificate is assumed trusted
	CertChain []Certificate `json:"cert_chain"`
	// RFC 3339 time format string, to check expiration against. If None,
	// certificate is assumed never expired
	NotAfter string `json:"not_after"`
}

type CertificateVerificationResponse struct {
	Trusted bool `json:"trusted"`
	// empty when trusted is true
	Reason string `json:"reason"`
}

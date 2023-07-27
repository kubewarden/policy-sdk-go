package crypto

import (
	"fmt"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"encoding/json"
)

type CryptoHost struct {
	cap.Host
}

// The encoding of the certificate
type CertificateEncoding int

const (
	Der CertificateEncoding = iota + 1
	Pem
)

func (e CertificateEncoding) MarshalJSON() ([]byte, error) {
	if e == Der {
		return json.Marshal("Der")
	} else if e == Pem {
		return json.Marshal("Pem")
	}

	return nil, fmt.Errorf("invalid certificate encoding")
}

// Verify_cert verifies cert's trust against the passed cert_chain, and
// expiration and validation time of the certificate.
// Accepts 3 arguments:
//   - cert: PEM/DER-encoded certificate to verify.
//   - cert_chain: list of PEM/DER-encoded certs, ordered by trust usage
//     (intermediates first, root last). If empty, certificate is assumed trusted.
//   - not_after: string in RFC 3339 time format, to check expiration against.
//     If None, certificate is assumed never expired.
func VerifyCert(h *cap.Host, cert Certificate, certChain []Certificate, notAfter string) (bool, error) {
	requestObj := CertificateVerificationRequest{
		Cert:      cert,
		CertChain: certChain,
		NotAfter:  notAfter,
	}

	payload, err := json.Marshal(requestObj)
	if err != nil {
		return false, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "crypto", "v1/is_certificate_trusted", payload)
	if err != nil {
		return false, err
	}

	responseObj := CertificateVerificationResponse{}
	if err := json.Unmarshal(responsePayload, &responseObj); err != nil {
		return false, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	if responseObj.Trusted {
		return true, nil
	} else {
		return false, fmt.Errorf(responseObj.Reason)
	}
}

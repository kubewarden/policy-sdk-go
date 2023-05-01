package crypto

import (
	"fmt"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/mailru/easyjson"
	jwriter "github.com/mailru/easyjson/jwriter"
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

func (e CertificateEncoding) MarshalEasyJSON(w *jwriter.Writer) {
	if e == Der {
		w.String("Der")
	} else if e == Pem {
		w.String("Pem")
	}
}

// Verify_cert verifies cert's trust against the passed cert_chain, and
// expiration and validation time of the certificate.
// Accepts 3 arguments:
//   - cert: PEM-encoded certificate to verify.
//   - cert_chain: list of PEM-encoded certs, ordered by trust usage
//     (intermediates first, root last). If empty, certificate is assumed trusted.
//   - not_after: string in RFC 3339 time format, to check expiration against.
//     If None, certificate is assumed never expired.
func VerifyCert(h *cap.Host, cert Certificate, certChain []Certificate, notAfter string) (bool, error) {
	requestObj := CertificateVerificationRequest{
		Cert:      cert,
		CertChain: certChain,
		NotAfter:  notAfter,
	}

	payload, err := easyjson.Marshal(requestObj)
	if err != nil {
		return false, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "crypto", "v1/is_certificate_trusted", payload)
	if err != nil {
		return false, err
	}

	responseObj := CertificateVerificationResponse{}
	if err := easyjson.Unmarshal(responsePayload, &responseObj); err != nil {
		return false, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	if responseObj.Trusted {
		return true, nil
	} else {
		return false, fmt.Errorf(responseObj.Reason)
	}
}

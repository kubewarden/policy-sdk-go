package capabilities

import jwriter "github.com/mailru/easyjson/jwriter"

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

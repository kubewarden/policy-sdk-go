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

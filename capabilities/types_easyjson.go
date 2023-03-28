// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package capabilities

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities(in *jlexer.Lexer, out *sigstorePubKeysVerify) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "image":
			out.Image = string(in.String())
		case "pub_keys":
			if in.IsNull() {
				in.Skip()
				out.PubKeys = nil
			} else {
				in.Delim('[')
				if out.PubKeys == nil {
					if !in.IsDelim(']') {
						out.PubKeys = make([]string, 0, 4)
					} else {
						out.PubKeys = []string{}
					}
				} else {
					out.PubKeys = (out.PubKeys)[:0]
				}
				for !in.IsDelim(']') {
					var v1 string
					v1 = string(in.String())
					out.PubKeys = append(out.PubKeys, v1)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "annotations":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Annotations = make(map[string]string)
				} else {
					out.Annotations = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v2 string
					v2 = string(in.String())
					(out.Annotations)[key] = v2
					in.WantComma()
				}
				in.Delim('}')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities(out *jwriter.Writer, in sigstorePubKeysVerify) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"image\":"
		out.RawString(prefix[1:])
		out.String(string(in.Image))
	}
	{
		const prefix string = ",\"pub_keys\":"
		out.RawString(prefix)
		if in.PubKeys == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v3, v4 := range in.PubKeys {
				if v3 > 0 {
					out.RawByte(',')
				}
				out.String(string(v4))
			}
			out.RawByte(']')
		}
	}
	if len(in.Annotations) != 0 {
		const prefix string = ",\"annotations\":"
		out.RawString(prefix)
		{
			out.RawByte('{')
			v5First := true
			for v5Name, v5Value := range in.Annotations {
				if v5First {
					v5First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v5Name))
				out.RawByte(':')
				out.String(string(v5Value))
			}
			out.RawByte('}')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v sigstorePubKeysVerify) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v sigstorePubKeysVerify) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *sigstorePubKeysVerify) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *sigstorePubKeysVerify) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities1(in *jlexer.Lexer, out *sigstoreKeylessVerify) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "image":
			out.Image = string(in.String())
		case "keyless":
			if in.IsNull() {
				in.Skip()
				out.Keyless = nil
			} else {
				in.Delim('[')
				if out.Keyless == nil {
					if !in.IsDelim(']') {
						out.Keyless = make([]KeylessInfo, 0, 2)
					} else {
						out.Keyless = []KeylessInfo{}
					}
				} else {
					out.Keyless = (out.Keyless)[:0]
				}
				for !in.IsDelim(']') {
					var v6 KeylessInfo
					(v6).UnmarshalEasyJSON(in)
					out.Keyless = append(out.Keyless, v6)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "annotations":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				if !in.IsDelim('}') {
					out.Annotations = make(map[string]string)
				} else {
					out.Annotations = nil
				}
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v7 string
					v7 = string(in.String())
					(out.Annotations)[key] = v7
					in.WantComma()
				}
				in.Delim('}')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities1(out *jwriter.Writer, in sigstoreKeylessVerify) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"image\":"
		out.RawString(prefix[1:])
		out.String(string(in.Image))
	}
	{
		const prefix string = ",\"keyless\":"
		out.RawString(prefix)
		if in.Keyless == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v8, v9 := range in.Keyless {
				if v8 > 0 {
					out.RawByte(',')
				}
				(v9).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	if len(in.Annotations) != 0 {
		const prefix string = ",\"annotations\":"
		out.RawString(prefix)
		{
			out.RawByte('{')
			v10First := true
			for v10Name, v10Value := range in.Annotations {
				if v10First {
					v10First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v10Name))
				out.RawByte(':')
				out.String(string(v10Value))
			}
			out.RawByte('}')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v sigstoreKeylessVerify) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v sigstoreKeylessVerify) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *sigstoreKeylessVerify) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *sigstoreKeylessVerify) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities1(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities2(in *jlexer.Lexer, out *VerificationResponse) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "is_trusted":
			out.IsTrusted = bool(in.Bool())
		case "digest":
			out.Digest = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities2(out *jwriter.Writer, in VerificationResponse) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"is_trusted\":"
		out.RawString(prefix[1:])
		out.Bool(bool(in.IsTrusted))
	}
	{
		const prefix string = ",\"digest\":"
		out.RawString(prefix)
		out.String(string(in.Digest))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v VerificationResponse) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities2(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v VerificationResponse) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities2(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *VerificationResponse) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities2(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *VerificationResponse) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities2(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities3(in *jlexer.Lexer, out *OciManifestResponse) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "digest":
			out.Digest = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities3(out *jwriter.Writer, in OciManifestResponse) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"digest\":"
		out.RawString(prefix[1:])
		out.String(string(in.Digest))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v OciManifestResponse) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities3(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v OciManifestResponse) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities3(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *OciManifestResponse) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities3(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *OciManifestResponse) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities3(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities4(in *jlexer.Lexer, out *LookupHostResponse) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "ips":
			if in.IsNull() {
				in.Skip()
				out.Ips = nil
			} else {
				in.Delim('[')
				if out.Ips == nil {
					if !in.IsDelim(']') {
						out.Ips = make([]string, 0, 4)
					} else {
						out.Ips = []string{}
					}
				} else {
					out.Ips = (out.Ips)[:0]
				}
				for !in.IsDelim(']') {
					var v11 string
					v11 = string(in.String())
					out.Ips = append(out.Ips, v11)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities4(out *jwriter.Writer, in LookupHostResponse) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"ips\":"
		out.RawString(prefix[1:])
		if in.Ips == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v12, v13 := range in.Ips {
				if v12 > 0 {
					out.RawByte(',')
				}
				out.String(string(v13))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v LookupHostResponse) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities4(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v LookupHostResponse) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities4(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *LookupHostResponse) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities4(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *LookupHostResponse) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities4(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities5(in *jlexer.Lexer, out *ListResourcesByNamespaceRequest) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "api_version":
			out.APIVersion = string(in.String())
		case "kind":
			out.Kind = string(in.String())
		case "namespace":
			out.Namespace = string(in.String())
		case "label_selector":
			out.LabelSelector = string(in.String())
		case "field_selector":
			out.FieldSelector = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities5(out *jwriter.Writer, in ListResourcesByNamespaceRequest) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"api_version\":"
		out.RawString(prefix[1:])
		out.String(string(in.APIVersion))
	}
	{
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		out.String(string(in.Kind))
	}
	{
		const prefix string = ",\"namespace\":"
		out.RawString(prefix)
		out.String(string(in.Namespace))
	}
	if in.LabelSelector != "" {
		const prefix string = ",\"label_selector\":"
		out.RawString(prefix)
		out.String(string(in.LabelSelector))
	}
	if in.FieldSelector != "" {
		const prefix string = ",\"field_selector\":"
		out.RawString(prefix)
		out.String(string(in.FieldSelector))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ListResourcesByNamespaceRequest) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities5(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ListResourcesByNamespaceRequest) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities5(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ListResourcesByNamespaceRequest) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities5(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ListResourcesByNamespaceRequest) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities5(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities6(in *jlexer.Lexer, out *ListAllResourcesRequest) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "api_version":
			out.APIVersion = string(in.String())
		case "kind":
			out.Kind = string(in.String())
		case "label_selector":
			out.LabelSelector = string(in.String())
		case "field_selector":
			out.FieldSelector = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities6(out *jwriter.Writer, in ListAllResourcesRequest) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"api_version\":"
		out.RawString(prefix[1:])
		out.String(string(in.APIVersion))
	}
	{
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		out.String(string(in.Kind))
	}
	if in.LabelSelector != "" {
		const prefix string = ",\"label_selector\":"
		out.RawString(prefix)
		out.String(string(in.LabelSelector))
	}
	if in.FieldSelector != "" {
		const prefix string = ",\"field_selector\":"
		out.RawString(prefix)
		out.String(string(in.FieldSelector))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ListAllResourcesRequest) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities6(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ListAllResourcesRequest) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities6(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ListAllResourcesRequest) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities6(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ListAllResourcesRequest) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities6(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities7(in *jlexer.Lexer, out *KeylessInfo) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "issuer":
			out.Issuer = string(in.String())
		case "subject":
			out.Subject = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities7(out *jwriter.Writer, in KeylessInfo) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"issuer\":"
		out.RawString(prefix[1:])
		out.String(string(in.Issuer))
	}
	{
		const prefix string = ",\"subject\":"
		out.RawString(prefix)
		out.String(string(in.Subject))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v KeylessInfo) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities7(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v KeylessInfo) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities7(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *KeylessInfo) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities7(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *KeylessInfo) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities7(l, v)
}
func easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities8(in *jlexer.Lexer, out *GetResourceRequest) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "api_version":
			out.APIVersion = string(in.String())
		case "kind":
			out.Kind = string(in.String())
		case "namespace":
			out.Namespace = string(in.String())
		case "name":
			out.Name = string(in.String())
		case "disable_cache":
			out.DisableCache = bool(in.Bool())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities8(out *jwriter.Writer, in GetResourceRequest) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"api_version\":"
		out.RawString(prefix[1:])
		out.String(string(in.APIVersion))
	}
	{
		const prefix string = ",\"kind\":"
		out.RawString(prefix)
		out.String(string(in.Kind))
	}
	{
		const prefix string = ",\"namespace\":"
		out.RawString(prefix)
		out.String(string(in.Namespace))
	}
	{
		const prefix string = ",\"name\":"
		out.RawString(prefix)
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"disable_cache\":"
		out.RawString(prefix)
		out.Bool(bool(in.DisableCache))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v GetResourceRequest) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities8(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetResourceRequest) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson6601e8cdEncodeGithubComKubewardenPolicySdkGoCapabilities8(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetResourceRequest) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities8(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetResourceRequest) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson6601e8cdDecodeGithubComKubewardenPolicySdkGoCapabilities8(l, v)
}

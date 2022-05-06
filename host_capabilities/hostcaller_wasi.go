// +build wasi

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package host_capabilities

import (
	"fmt"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	wapc "github.com/wapc/wapc-guest-tinygo"
)

// NewWASIHostCaller creates a HostCaller in the wasi target, that will be used
// in the wasm-compiled policy.
func NewWASIHostCaller() HostCaller {
	return wasiHostCaller{}
}

type wasiHostCaller struct{}

func (wasiHostCaller) GetOCIManifest(image string) (digest string, err error) {
	// build request, e.g: `{"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"}`
	request := make([]byte, 0)
	if request, err = sjson.SetBytes(request, "", []byte(image)); err != nil {
		return "", err
	}

	// perform host callback
	response, err := wapc.HostCall("kubewarden", "oci", "manifest_digest", request)
	if err != nil {
		return "", err
	}

	// extract digest from response
	digest = gjson.GetBytes(response, "").String()
	return digest, err
}

func (wasiHostCaller) LookupHost(host string) (listIPs []string, err error) {
	// build request, e.g: `{"localhost"}`
	request := make([]byte, 0)
	if request, err = sjson.SetBytes(request, "", []byte(host)); err != nil {
		return nil, err
	}

	// perform host callback
	response, err := wapc.HostCall("kubewarden", "net", "dns_lookup_host", request)
	if err != nil {
		return nil, err
	}

	// extract listIPs from response
	result := gjson.GetBytes(response, "")
	result.ForEach(func(key, value gjson.Result) bool {
		listIPs = append(listIPs, value.String())
		println(value.String())
		return true // keep iterating
	})

	return listIPs, err
}

func (wasiHostCaller) VerifyPubKeys(image string, pubKeys []string, annotations map[string]string) (vr VerificationResponse, err error) {
	// failsafe return response
	vr = VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	// build request, e.g:
	// {
	//   "image": <string>,
	//   "pub_keys": [
	//     <string>
	//   ],
	//   "annotations": [
	//     {
	//       "key": <string>,
	//       "value": <string>
	//     },
	//   ]
	// }
	request := make([]byte, 0)
	if request, err = sjson.SetBytes(request, "image", []byte(image)); err != nil {
		return vr, err
	}
	for _, pubkey := range pubKeys {
		// append current pubkey:
		if request, err = sjson.SetBytes(request, "pub_keys.-1", []byte(pubkey)); err != nil {
			return vr, err
		}
	}
	for k, v := range annotations {
		// build json object with key value. We don't know if structs passed to sjson.SetBytes() would work
		// {
		//    "key": "foo",
		//    "value": "bar",
		// }
		annotation := fmt.Sprint("{\"key\": \"", k, "\",\"value\": \"", v, "\",}")
		// append the current annotation:
		if request, err = sjson.SetBytes(request, "annotations.-1", []byte(annotation)); err != nil {
			return vr, err
		}
	}

	// perform callback
	response, err := wapc.HostCall("kubewarden", "oci", "v1/verify", request)
	if err != nil {
		return vr, err
	} else {
		vr.IsTrusted = gjson.GetBytes(response, "is_trusted").Bool()
		vr.Digest = gjson.GetBytes(response, "digest").String()
		return vr, nil
	}
}

func (wasiHostCaller) VerifyKeyless(image string, keyless []KeylessInfo, annotations map[string]string) (vr VerificationResponse, err error) {
	// failsafe return response
	vr = VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	// build request, e.g:
	// {
	//   "image": <string>,
	//   "keyless": [
	//    {
	//      "issuer": <string>,
	//      "subject": <string>,
	//    }
	// 	 ],
	//   "annotations": [
	//     {
	//       "key": <string>,
	//       "value": <string>
	//     },
	//   ]
	// }
	request := make([]byte, 0)
	if request, err = sjson.SetBytes(request, "image", []byte(image)); err != nil {
		return vr, err
	}
	for _, v := range keyless {
		// build current keyless issuerSubject tuple:
		issuerSubject := fmt.Sprint("{\"issuer\": \"", v.Issuer, "\",\"subject\": \"", v.Subject, "\",}")
		// append current keyless tuple:
		if request, err = sjson.SetBytes(request, "keyless.-1", []byte(issuerSubject)); err != nil {
			return vr, err
		}
	}
	for k, v := range annotations {
		// build json object with key value. We don't know if structs passed to sjson.SetBytes() would work
		// {
		//    "key": "foo",
		//    "value": "bar",
		// }
		annotation := fmt.Sprint("{\"key\": \"", k, "\",\"value\": \"", v, "\",}")
		// append the current annotation:
		if request, err = sjson.SetBytes(request, "annotations.-1", []byte(annotation)); err != nil {
			return vr, err
		}
	}

	// perform callback
	response, err := wapc.HostCall("kubewarden", "oci", "v1/verify", request)
	if err != nil {
		return vr, err
	} else {
		vr.IsTrusted = gjson.GetBytes(response, "is_trusted").Bool()
		vr.Digest = gjson.GetBytes(response, "digest").String()
		return vr, nil
	}
}

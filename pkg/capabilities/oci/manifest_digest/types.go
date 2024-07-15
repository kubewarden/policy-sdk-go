package manifest_digest

// We don't need to expose that to consumers of the library
// This is a glorified wrapper needed to unmarshal a string
// inside of TinyGo. As of release 0.29.0, unmarshal a simple
// string causes a runtime panic.
type OciManifestResponse struct {
	// digest of the image
	Digest string `json:"digest"`
}

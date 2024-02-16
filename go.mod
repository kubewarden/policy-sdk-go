module github.com/kubewarden/policy-sdk-go

go 1.21

require (
	github.com/golang/mock v1.6.0
	github.com/wapc/wapc-guest-tinygo v0.3.3
)

require github.com/go-openapi/strfmt v0.21.3 // indirect

require (
	github.com/google/go-cmp v0.6.0
	github.com/kubewarden/k8s-objects v1.29.0-kw1
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

module github.com/kubewarden/policy-sdk-go

go 1.22

require github.com/wapc/wapc-guest-tinygo v0.3.3

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/google/go-cmp v0.7.0
	github.com/kubewarden/k8s-objects v1.29.0-kw1
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/stretchr/testify v1.11.0
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

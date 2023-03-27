module github.com/kubewarden/policy-sdk-go

go 1.20

require (
	github.com/mailru/easyjson v0.7.7
	github.com/wapc/wapc-guest-tinygo v0.3.3
)

require github.com/go-openapi/strfmt v0.21.3 // indirect

require (
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kubewarden/k8s-objects v1.24.0-kw6
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.2

package kubernetes

// ListResourcesByNamespaceRequest represents a set of parameters used by the `list_resources_by_namespace` function.
type ListResourcesByNamespaceRequest struct {
	// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
	APIVersion string `json:"api_version"`
	// Singular PascalCase name of the resource
	Kind string `json:"kind"`
	// Namespace scoping the search
	Namespace string `json:"namespace"`
	// A selector to restrict the list of returned objects by their labels.
	// Defaults to everything if omitted
	LabelSelector *string `json:"label_selector,omitempty"`
	// A selector to restrict the list of returned objects by their fields.
	// Defaults to everything if omitted
	FieldSelector *string `json:"field_selector,omitempty"`
}

// ListAllResourcesRequest represents a set of parameters used by the `list_all_resources` function.
type ListAllResourcesRequest struct {
	// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
	APIVersion string `json:"api_version"`
	// Singular PascalCase name of the resource
	Kind string `json:"kind"`
	// A selector to restrict the list of returned objects by their labels.
	// Defaults to everything if omitted
	LabelSelector *string `json:"label_selector,omitempty"`
	// A selector to restrict the list of returned objects by their fields.
	// Defaults to everything if omitted
	FieldSelector *string `json:"field_selector,omitempty"`
}

// GetResourceRequest represents a set of parameters used by the `get_resource` function.
type GetResourceRequest struct {
	APIVersion string `json:"api_version"`
	// Singular PascalCase name of the resource
	Kind string `json:"kind"`
	// The name of the resource
	Name string `json:"name"`
	// Namespace scoping the search
	Namespace *string `json:"namespace,omitempty"`
	// Disable caching of results obtained from Kubernetes API Server
	// By default query results are cached for 5 seconds, that might cause
	// stale data to be returned.
	// However, making too many requests against the Kubernetes API Server
	// might cause issues to the cluster
	DisableCache bool `json:"disable_cache"`
}

// SubjectAccessReviewRequest represents an  authorization.k9s.io/v1
// SubjectAccessReview, used by the `can_i` function.
type SubjectAccessReviewRequest struct {
	// APIVersion defines the versioned schema of the representation of the
	// object
	APIVersion string `json:"apiVersion"`
	// Kind is the Singular PascalCase name of the resource
	Kind string `json:"kind"`
	// Spec of the SubjectAccessReview
	Spec SubjectAccessReviewSpec `json:"spec"`
	// Disable caching of results obtained from Kubernetes API Server
	// By default query results are cached for 5 seconds, that might cause
	// stale data to be returned.
	// However, making too many requests against the Kubernetes API Server
	// might cause issues to the cluster
	DisableCache bool `json:"disable_cache"`
}

// SubjectAccessReviewSpec represents the spec field for a SubjectAccessReview.
type SubjectAccessReviewSpec struct {
	// ResourceAttributes includes the authorization attributes available for
	// resource requests to the Authorizer interface
	ResourceAttributes ResourceAttributes `json:"resourceAttributes"`
	// User is the user you’re testing for. If you specify "User" but not
	// "Groups", then is it interpreted as "What if User were not a member of any
	// groups.
	// The user specified must match the user being validated by the policy. For
	// example, to validate a service account named my-user in the default
	// namespace, the user field in the spec should be set to
	// system:serviceaccount:default:my-user.
	User string `json:"user"`
	// Groups is the groups you’re testing for.
	Groups []string `json:"groups"`
}

// ResourceAttributes describes information for a resource request.
type ResourceAttributes struct {
	// Namespace is the namespace of the action being requested. Currently, there
	// is no distinction between no namespace and all namespaces "" (empty)
	Namespace string `json:"namespace"`
	// Verb is a kubernetes resource API verb, like: get, list, watch, create,
	// update, patch, delete, deletecollection, proxy. “*” means all.
	Verb string `json:"verb"`
	// Group is the API Group of the Resource. “*” means all.
	Group string `json:"group"`
	// Resource is one of the existing resource types. “*” means all.
	Resource string `json:"resource"`
}

// SubjectAccessReviewStatus holds the result of the `can_i` function.
// Analogous to authorization.k9s.io/v1 SubjectAccessReviewStatus.
type SubjectAccessReviewStatus struct {
	// True if the action would be allowed, false otherwise.
	Allowed bool `json:"allowed"`
	// Optional. True if the action would be denied, otherwise false. If both
	// allowed is false and denied is false, then the authorizer has no opinion
	// on whether to authorize the action.
	// Denied may not be true if Allowed is true.
	Denied bool `json:"denied,omitempty"`
	// Optional. Indicates why a request was allowed or denied.
	Reason string `json:"reason,omitempty"`
	// Optional. Is an indication that some error occurred during the
	// authorization check. It is entirely possible to get an error and be able
	// to continue determine authorization status in spite of it. For instance,
	// RBAC can be missing a role, but enough roles are still present and bound
	// to reason about the request.
	EvaluationError string `json:"evaluationError,omitempty"`
}

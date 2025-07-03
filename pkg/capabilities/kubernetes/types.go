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
	APIVersion string `json:"apiVersion"`
	// Singular PascalCase name of the resource
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
	ResourceAttributes ResourceAttributes `json:"resourceAttributes"`
	User               string             `json:"user"`
	Groups             []string           `json:"groups"`
}

// ResourceAttributes describes information for a resource request.
type ResourceAttributes struct {
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`
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

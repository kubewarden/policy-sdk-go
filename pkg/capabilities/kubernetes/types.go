package kubernetes

// Set of parameters used by the `list_resources_by_namespace` function
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

// Set of parameters used by the `list_all_resources` function
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

// Set of parameters used by the `get_resource` function
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

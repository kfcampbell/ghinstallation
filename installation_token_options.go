package ghinstallation

import (
	gh "github.com/octokit/go-sdk/pkg/github/models"
)

// InstallationTokenOptions allow restricting a token's access to specific repositories.
type InstallationTokenOptions struct {
	// The IDs of the repositories that the installation token can access.
	// Providing repository IDs restricts the access of an installation token to specific repositories.
	RepositoryIDs []int64 `json:"repository_ids,omitempty"`

	// The names of the repositories that the installation token can access.
	// Providing repository names restricts the access of an installation token to specific repositories.
	Repositories []string `json:"repositories,omitempty"`

	// The permissions granted to the access token.
	// The permissions object includes the permission names and their access type.
	Permissions *gh.AppPermissions `json:"permissions,omitempty"`
}

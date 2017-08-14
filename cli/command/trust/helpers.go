package trust

import (
	"context"
	"fmt"

	"strings"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/registry"
	"github.com/docker/notary/tuf/data"
)

func getImageReferencesAndAuth(cli command.Cli, imgName string) (context.Context, reference.Named, *registry.RepositoryInfo, *types.AuthConfig, error) {
	ref, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)
	return ctx, ref, repoInfo, &authConfig, err
}

func getTag(ref reference.Named) (string, error) {
	var tag string
	switch x := ref.(type) {
	case reference.Canonical:
		return "", fmt.Errorf("cannot display trust info for a digest reference")
	case reference.NamedTagged:
		tag = x.Tag()
	default:
		tag = ""
	}
	return tag, nil
}

// check if a role name is "released": either targets/releases or targets TUF roles
func isReleasedTarget(role data.RoleName) bool {
	return role == data.CanonicalTargetsRole || role == trust.ReleasesRole
}

// convert TUF role name to a human-understandable signer name
func notaryRoleToSigner(tufRole data.RoleName) string {
	//  don't show a signer for "targets" or "targets/releases"
	if isReleasedTarget(data.RoleName(tufRole.String())) {
		return releasedRoleName
	}
	return strings.TrimPrefix(tufRole.String(), "targets/")
}

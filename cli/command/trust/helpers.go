package trust

import (
	"context"

	"github.com/docker/cli/cli/command"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/registry"
)

func getImageReferencesAndAuth(cli command.Cli, imgName string) (reference.Named, *registry.RepositoryInfo, *types.AuthConfig, error) {
	ref, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return nil, nil, nil, err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)
	return ref, repoInfo, &authConfig, err
}

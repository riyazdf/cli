package trust

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/docker/notary"
	"github.com/spf13/cobra"
)

func newInfoCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [OPTIONS] IMAGE",
		Short: "Display detailed information about keys and signatures",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return lookupTrustInfo(dockerCli, args[0])
		},
	}
	return cmd
}

func lookupTrustInfo(cli command.Cli, remote string) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, authConfig, "pull")
	if err != nil {
		fmt.Fprintf(cli.Out(), "Error establishing connection to notary repository: %s\n", err)
		return err
	}

	targetList, err := notaryRepo.ListTargets("")
	if err != nil {
		// TODO(riyazdf): switch on error types for better messaging if not signed vs. other things
		fmt.Fprintf(cli.Out(), "Error retrieving tags from notary repository: %s\n", err)
		return err
	}
	fmt.Fprintf(cli.Out(), "SIGNATURE DATA FOR %s:\n\n", remote)
	for _, tgt := range targetList {
		prettyHash := base64.StdEncoding.EncodeToString(tgt.Hashes[notary.SHA256])
		fmt.Fprintf(cli.Out(), "%s\t%s\t%d\t%s\n", tgt.Name, prettyHash, tgt.Length, tgt.Role)
	}

	return nil
}

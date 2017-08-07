package trust

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
)

func newRevokeCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [OPTIONS] IMAGE[:TAG]",
		Short: "Remove trust for an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return revokeTrust(dockerCli, args[0])
		},
	}
	return cmd
}

func askConfirm(input io.Reader) bool {
	var res string
	if _, err := fmt.Fscanln(input, &res); err != nil {
		return false
	}
	if strings.EqualFold(res, "y") || strings.EqualFold(res, "yes") {
		return true
	}
	return false
}

func revokeTrust(cli command.Cli, remote string) error {
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}
	switch ref.(type) {
	case reference.Digested, reference.Canonical:
		return fmt.Errorf("Cannot remove signature for digest")
	case reference.NamedTagged:
		return revokeSingleSig(cli, ref.(reference.NamedTagged))
	default:
		return revokeAllSigs(cli, ref)
	}
}

func revokeSingleSig(cli command.Cli, ref reference.NamedTagged) error {
	tag := ref.Tag()

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)

	// TODO(riyazdf): can we allow for a memory changelist?
	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, authConfig, "push")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	// Figure out which roles this is published to and which keys we have on-disk
	targetSigs, err := notaryRepo.GetAllTargetMetadataByName(tag)
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	roles := []data.RoleName{}
	for _, sig := range targetSigs {
		roles = append(roles, sig.Role.Name)
	}

	// TODO: check which role the target is signed into and do some key-matching against what the user has
	// in particular: should check if it's in targets/releases first, and then targets
	// if the user doesn't have any helpful keys, error out early

	// Remove from all roles
	if err := notaryRepo.RemoveTarget(tag, roles...); err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	// Publish change
	return notaryRepo.Publish()
}

func revokeAllSigs(cli command.Cli, ref reference.Named) error {
	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	in := os.Stdin
	fmt.Printf(
		"Please confirm you would like to delete all signature data for: %s (y/n)\n",
		repoInfo.Name,
	)
	// TODO: Also add force (-y) flag
	deleteRemote := askConfirm(in)
	if !deleteRemote {
		fmt.Println("\nAborting action.")
		return nil
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)
	server, err := trust.Server(repoInfo.Index)
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	tr, err := trust.GetTransport(repoInfo, server, authConfig, "*")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	notaryRepo, err := trust.GetNotaryRepositoryWithTransport(cli, repoInfo, server, tr)
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	fmt.Printf("notary repo: %+v", notaryRepo)

	// Use function below to purge
	client.DeleteTrustData(
		notaryRepo.baseDir,
		notaryRepo.gun,
		notaryRepo.baseURL,
		tr,
		deleteRemote)

	return nil
}

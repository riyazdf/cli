package trust

import (
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
	"github.com/docker/docker/api/types"
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
	ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, remote)
	if err != nil {
		return err
	}
	switch ref.(type) {
	case reference.Digested, reference.Canonical:
		return fmt.Errorf("cannot remove signature for digest")
	case reference.NamedTagged:

		if err := revokeSingleSig(cli, ref.(reference.NamedTagged), repoInfo, *authConfig); err != nil {
			return fmt.Errorf("could not remove signature for %s: %s", remote, err)
		}
		fmt.Fprintf(cli.Out(), "Successfully deleted signature for %s\n", remote)
		return nil
	default:
		in := os.Stdin
		fmt.Fprintf(
			cli.Out(),
			"Please confirm you would like to delete all signature data for %s? (y/n)\n",
			remote,
		)
		// TODO: Also add force (-y) flag
		deleteRemote := askConfirm(in)
		if !deleteRemote {
			fmt.Fprintf(cli.Out(), "\nAborting action.\n")
			return nil
		}
		if err := revokeAllSigs(cli, ref, repoInfo, *authConfig); err != nil {
			return fmt.Errorf("could not remove all signatures for %s: %s", remote, err)
		}

		fmt.Fprintf(cli.Out(), "Successfully deleted all signature data for %s\n", remote)
		return nil
	}
}

func revokeSingleSig(cli command.Cli, ref reference.NamedTagged, repoInfo *registry.RepositoryInfo, authConfig types.AuthConfig) error {
	tag := ref.Tag()
	// TODO(riyazdf): can we allow for a memory changelist?
	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, authConfig, "push", "pull")
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
	if err := notaryRepo.Publish(); err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	return nil
}

func revokeAllSigs(cli command.Cli, ref reference.Named, repoInfo *registry.RepositoryInfo, authConfig types.AuthConfig) error {
	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, authConfig, "*")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	targetList, err := notaryRepo.ListTargets()
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	releasedTargetList := []client.Target{}
	for _, targetWithRole := range targetList {
		target := targetWithRole.Target
		releasedTargetList = append(releasedTargetList, target)
	}

	// we need all the roles that signed each released target so we can remove from all roles.
	for _, releasedTarget := range releasedTargetList {
		signableRoles, err := getSignableRoles(notaryRepo, &releasedTarget)
		if err != nil {
			return trust.NotaryError(ref.Name(), err)
		}
		roles := []data.RoleName{}
		roles = append(roles, signableRoles...)
		// remove from all roles
		if err := notaryRepo.RemoveTarget(releasedTarget.Name, roles...); err != nil {
			return trust.NotaryError(ref.Name(), err)
		}
	}
	// Publish change
	if err := notaryRepo.Publish(); err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	return nil
}

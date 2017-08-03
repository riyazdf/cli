package trust

import (
	"fmt"
	"path"
	"sort"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
)

func newSignCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign [OPTIONS] IMAGE TAG",
		Short: "Sign an image",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return signImage(dockerCli, args[0], args[1])
		},
	}
	return cmd
}

func signImage(cli command.Cli, image, tag string) error {
	ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, image)
	if err != nil {
		return err
	}

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, *authConfig, "push", "pull")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	fmt.Fprintf(cli.Out(), "Signing and pushing trust metadata for %s:%s\n", image, tag)

	// get the latest repository metadata so we can figure out which roles to sign
	if err = notaryRepo.Update(false); err != nil {
		switch err.(type) {
		case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
			userRole := data.RoleName(path.Join(data.CanonicalTargetsRole.String(), authConfig.Username))
			if err := initNotaryRepoWithSigners(cli, notaryRepo, userRole); err != nil {
				return trust.NotaryError(ref.Name(), err)
			}
			fmt.Fprintf(cli.Out(), "Created signer: %s\n", authConfig.Username)
		default:
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
	}

	// TODO: craft and sign the target using image.addTargetToAllSignableRoles (needs to be exported)
	return nil
}

func initNotaryRepoWithSigners(cli command.Cli, notaryRepo *client.NotaryRepository, newSigner data.RoleName) error {
	keys := notaryRepo.CryptoService.ListKeys(data.CanonicalRootRole)
	var err error
	var rootKeyID string
	// always select the first root key
	if len(keys) > 0 {
		sort.Strings(keys)
		rootKeyID = keys[0]
	} else {
		rootPublicKey, err := notaryRepo.CryptoService.Create(data.CanonicalRootRole, "", data.ECDSAKey)
		if err != nil {
			return err
		}
		rootKeyID = rootPublicKey.ID()
	}

	// Initialize the notary repository with a remotely managed snapshot key
	if err := notaryRepo.Initialize([]string{rootKeyID}, data.CanonicalSnapshotRole); err != nil {
		return trust.NotaryError(notaryRepo.GetGUN().String(), err)
	}

	// Check if we have a user key
	var signerKey data.PublicKey
	signerKeys := notaryRepo.CryptoService.ListKeys(newSigner)
	if len(signerKeys) > 0 {
		sort.Strings(signerKeys)
		signerKeyID := signerKeys[0]
		signerKey = notaryRepo.CryptoService.GetKey(signerKeyID)
	} else {
		signerKey, err = notaryRepo.CryptoService.Create(newSigner, "", data.ECDSAKey)
		if err != nil {
			return err
		}
	}

	// create targets/<username>
	notaryRepo.AddDelegationRoleAndKeys(newSigner, []data.PublicKey{signerKey})
	notaryRepo.AddDelegationPaths(newSigner, []string{""})

	// create targets/releases
	notaryRepo.AddDelegationRoleAndKeys(trust.ReleasesRole, []data.PublicKey{signerKey})
	notaryRepo.AddDelegationPaths(trust.ReleasesRole, []string{""})

	if err := notaryRepo.Publish(); err != nil {
		return err
	}
	fmt.Fprintf(cli.Out(), "Finished initializing %q\n", notaryRepo.GetGUN().String())
	return nil
}

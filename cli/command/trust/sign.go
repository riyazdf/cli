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
			if err := initNotaryRepoWithSigners(notaryRepo, userRole); err != nil {
				return trust.NotaryError(ref.Name(), err)
			}

			fmt.Fprintf(cli.Out(), "Created signer: %s\n", authConfig.Username)
			fmt.Fprintf(cli.Out(), "Finished initializing %q\n", notaryRepo.GetGUN().String())
		default:
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
	}

	// TODO: craft and sign the target using image.addTargetToAllSignableRoles (needs to be exported)
	return nil
}

func initNotaryRepoWithSigners(notaryRepo *client.NotaryRepository, newSigner data.RoleName) error {
	rootKey, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	if err != nil {
		return err
	}
	rootKeyID := rootKey.ID()

	// Initialize the notary repository with a remotely managed snapshot key
	if err := notaryRepo.Initialize([]string{rootKeyID}, data.CanonicalSnapshotRole); err != nil {
		return err
	}

	signerKey, err := getOrGenerateNotaryKey(notaryRepo, newSigner)
	if err != nil {
		return err
	}
	addStagedSigner(notaryRepo, newSigner, []data.PublicKey{signerKey})

	return notaryRepo.Publish()
}

// generates an ECDSA key without a GUN for the specified role
func getOrGenerateNotaryKey(notaryRepo *client.NotaryRepository, role data.RoleName) (data.PublicKey, error) {
	keys := notaryRepo.CryptoService.ListKeys(role)
	var err error
	var key data.PublicKey
	// always select the first key by ID
	if len(keys) > 0 {
		sort.Strings(keys)
		keyID := keys[0]
		privKey, _, err := notaryRepo.CryptoService.GetPrivateKey(keyID)
		if err != nil {
			return nil, err
		}
		key = data.PublicKeyFromPrivate(privKey)
	} else {
		key, err = notaryRepo.CryptoService.Create(role, "", data.ECDSAKey)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

// stages changes to add a signer with the specified name and key(s).  Adds to targets/<name> and targets/releases
func addStagedSigner(notaryRepo *client.NotaryRepository, newSigner data.RoleName, signerKeys []data.PublicKey) {
	// create targets/<username>
	notaryRepo.AddDelegationRoleAndKeys(newSigner, signerKeys)
	notaryRepo.AddDelegationPaths(newSigner, []string{""})

	// create targets/releases
	notaryRepo.AddDelegationRoleAndKeys(trust.ReleasesRole, signerKeys)
	notaryRepo.AddDelegationPaths(trust.ReleasesRole, []string{""})
}

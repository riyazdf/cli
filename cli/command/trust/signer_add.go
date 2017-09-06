package trust

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/opts"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	tufutils "github.com/docker/notary/tuf/utils"
	"github.com/spf13/cobra"
)

type signerAddOptions struct {
	keys   opts.ListOpts
	signer string
	images []string
}

func newSignerAddCommand(dockerCli command.Cli) *cobra.Command {
	var options signerAddOptions
	cmd := &cobra.Command{
		Use:   "signer-add [OPTIONS] NAME IMAGE [IMAGE...] ",
		Short: "Add a signer",
		Args:  cli.RequiresMinArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			options.signer = args[0]
			options.images = args[1:]
			return addSigner(dockerCli, &options)
		},
	}
	flags := cmd.Flags()
	options.keys = opts.NewListOpts(nil)
	flags.VarP(&options.keys, "key", "k", "Path to the signer's public key(s)")
	return cmd
}

func addSigner(cli command.Cli, options *signerAddOptions) error {
	signerName := options.signer

	if signerName == "releases" {
		return fmt.Errorf("releases is a reserved keyword, please use a different signer name")
	}

	if options.keys.Len() < 1 {
		return fmt.Errorf("path to a valid public key must be provided using the `--key` flag")
	}

	for _, imageName := range options.images {
		if err := addSignerToImage(cli, signerName, imageName, options.keys.GetAll()); err != nil {
			fmt.Fprintf(cli.Out(), "Failed to add signer to %s: %s\n", imageName, err)
			continue
		}
		fmt.Fprintf(cli.Out(), "Successfully added signer: %s to %s\n", signerName, imageName)
	}
	return nil
}

func addSignerToImage(cli command.Cli, signerName string, imageName string, keyPaths []string) error {
	_, ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, imageName)
	if err != nil {
		return err
	}

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, *authConfig, "push", "pull")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	if err = notaryRepo.Update(false); err != nil {
		switch err.(type) {
		case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
			fmt.Fprintf(cli.Out(), "Initializing signed repository for %s...\n", imageName)
			if err := getOrGenerateRootKeyAndInitRepo(notaryRepo); err != nil {
				return trust.NotaryError(ref.Name(), err)
			}
			fmt.Fprintf(cli.Out(), "Successfully initialized %q\n", imageName)
		default:
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
	}

	fmt.Fprintf(cli.Out(), "\nAdding signer \"%s\" to %s...\n", signerName, imageName)
	newSignerRoleName := data.RoleName(path.Join(data.CanonicalTargetsRole.String(), signerName))

	signerPubKeys, err := ingestPublicKeys(keyPaths)
	if err != nil {
		return err
	}
	addStagedSigner(notaryRepo, newSignerRoleName, signerPubKeys)

	return notaryRepo.Publish()
}

func ingestPublicKeys(pubKeyPaths []string) ([]data.PublicKey, error) {
	pubKeys := []data.PublicKey{}
	for _, pubKeyPath := range pubKeyPaths {
		// Read public key bytes from PEM file
		pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("file for public key does not exist: %s", pubKeyPath)
			}
			return nil, fmt.Errorf("unable to read public key from file: %s", pubKeyPath)
		}

		// Parse PEM bytes into type PublicKey
		pubKey, err := tufutils.ParsePEMPublicKey(pubKeyBytes)
		if err != nil {
			return nil, err
		}
		pubKeys = append(pubKeys, pubKey)
	}
	return pubKeys, nil
}

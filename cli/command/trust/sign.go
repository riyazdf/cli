package trust

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/image"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
)

func newSignCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign [OPTIONS] IMAGE:TAG",
		Short: "Sign an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return signImage(dockerCli, args[0])
		},
	}
	return cmd
}

func signImage(cli command.Cli, imageName string) error {
	ctx, ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, imageName)
	if err != nil {
		return err
	}

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, *authConfig, "push", "pull")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	if err = clearChangeList(notaryRepo); err != nil {
		return err
	}
	defer clearChangeList(notaryRepo)
	tag, err := getTag(ref)
	if err != nil {
		return err
	}
	if tag == "" {
		return fmt.Errorf("No tag specified for %s", imageName)
	}

	// get the latest repository metadata so we can figure out which roles to sign
	if err = notaryRepo.Update(false); err != nil {
		switch err.(type) {
		case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
			// before initializing a new repo, check that the image exists locally:
			if err := checkLocalImageExistence(ctx, cli, imageName); err != nil {
				return err
			}

			userRole := data.RoleName(path.Join(data.CanonicalTargetsRole.String(), authConfig.Username))
			if err := initNotaryRepoWithSigners(notaryRepo, userRole); err != nil {
				return trust.NotaryError(ref.Name(), err)
			}

			fmt.Fprintf(cli.Out(), "Created signer: %s\n", authConfig.Username)
			fmt.Fprintf(cli.Out(), "Finished initializing signed repository for %s\n", imageName)
		default:
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
	}
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(cli, repoInfo.Index, "push")
	target, err := createTarget(notaryRepo, tag)
	if err != nil {
		switch err := err.(type) {
		case client.ErrNoSuchTarget, client.ErrRepositoryNotExist:
			// Fail fast if the image doesn't exist locally
			if err := checkLocalImageExistence(ctx, cli, imageName); err != nil {
				return err
			}
			return image.TrustedPush(ctx, cli, repoInfo, ref, *authConfig, requestPrivilege)
		default:
			return err
		}
	}

	fmt.Fprintf(cli.Out(), "Signing and pushing trust metadata for %s\n", imageName)
	existingSigInfo, err := getExistingSignatureInfoForReleasedTag(notaryRepo, tag)
	if err != nil {
		return err
	}
	err = image.AddTargetToAllSignableRoles(notaryRepo, &target)
	if err == nil {
		prettyPrintExistingSignatureInfo(cli, existingSigInfo)
		err = notaryRepo.Publish()
	}
	if err != nil {
		return fmt.Errorf("failed to sign %q:%s - %s", repoInfo.Name.Name(), tag, err.Error())
	}
	fmt.Fprintf(cli.Out(), "Successfully signed %q:%s\n", repoInfo.Name.Name(), tag)
	return nil
}

func createTarget(notaryRepo *client.NotaryRepository, tag string) (client.Target, error) {
	target := &client.Target{}
	var err error
	if tag == "" {
		return *target, fmt.Errorf("No tag specified")
	}
	target.Name = tag
	target.Hashes, target.Length, err = getSignedManifestHashAndSize(notaryRepo, tag)
	return *target, err
}

func getSignedManifestHashAndSize(notaryRepo *client.NotaryRepository, tag string) (data.Hashes, int64, error) {
	targets, err := notaryRepo.GetAllTargetMetadataByName(tag)
	if err != nil {
		return nil, 0, err
	}
	return getReleasedTargetHashAndSize(targets, tag)
}

func getReleasedTargetHashAndSize(targets []client.TargetSignedStruct, tag string) (data.Hashes, int64, error) {
	for _, tgt := range targets {
		if isReleasedTarget(tgt.Role.Name) {
			return tgt.Target.Hashes, tgt.Target.Length, nil
		}
	}
	return nil, 0, client.ErrNoSuchTarget(tag)
}

func getExistingSignatureInfoForReleasedTag(notaryRepo *client.NotaryRepository, tag string) (trustTagRow, error) {
	targets, err := notaryRepo.GetAllTargetMetadataByName(tag)
	if err != nil {
		return trustTagRow{}, err
	}
	releasedTargetInfoList := matchReleasedSignatures(targets)
	if len(releasedTargetInfoList) == 0 {
		return trustTagRow{}, nil
	}
	return releasedTargetInfoList[0], nil
}

func prettyPrintExistingSignatureInfo(cli command.Cli, existingSigInfo trustTagRow) {
	sort.Strings(existingSigInfo.Signers)
	joinedSigners := strings.Join(existingSigInfo.Signers, ", ")
	fmt.Fprintf(cli.Out(), "Existing signatures for tag %s digest %s from:\n%s\n", existingSigInfo.TagName, existingSigInfo.HashHex, joinedSigners)
}

func initNotaryRepoWithSigners(notaryRepo *client.NotaryRepository, newSigner data.RoleName) error {
	if err := getOrGenerateRootKeyAndInitRepo(notaryRepo); err != nil {
		return err
	}

	signerKey, err := getOrGenerateNotaryKey(notaryRepo, newSigner)
	if err != nil {
		return err
	}
	addStagedSigner(notaryRepo, newSigner, []data.PublicKey{signerKey})

	return notaryRepo.Publish()
}

package trust

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/image"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/docker/api/types"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type signOptions struct {
	local bool
}

func newSignCommand(dockerCli command.Cli) *cobra.Command {
	options := signOptions{}
	cmd := &cobra.Command{
		Use:   "sign [OPTIONS] IMAGE:TAG",
		Short: "Sign an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return signImage(dockerCli, args[0], options)
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&options.local, "local", "", false, "Sign a locally tagged image")
	return cmd
}

func signImage(cli command.Cli, imageName string, options signOptions) error {
	ctx := context.Background()
	authResolver := func(ctx context.Context, index *registrytypes.IndexInfo) types.AuthConfig {
		return command.ResolveAuthConfig(ctx, cli, index)
	}
	imgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, authResolver, imageName)
	if err != nil {
		return err
	}
	tag := imgRefAndAuth.Tag()
	if tag == "" {
		if imgRefAndAuth.Digest() != "" {
			return fmt.Errorf("cannot use a digest reference for IMAGE:TAG")
		}
		return fmt.Errorf("No tag specified for %s", imageName)
	}

	notaryRepo, err := cli.NotaryClient(*imgRefAndAuth, trust.ActionsPushAndPull)
	if err != nil {
		return trust.NotaryError(imgRefAndAuth.Reference().Name(), err)
	}
	if err = clearChangeList(notaryRepo); err != nil {
		return err
	}
	defer clearChangeList(notaryRepo)

	// get the latest repository metadata so we can figure out which roles to sign
	if _, err = notaryRepo.ListTargets(); err != nil {
		switch err.(type) {
		case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
			// before initializing a new repo, check that the image exists locally:
			if err := checkLocalImageExistence(ctx, cli, imageName); err != nil {
				return err
			}

			userRole := data.RoleName(path.Join(data.CanonicalTargetsRole.String(), imgRefAndAuth.AuthConfig().Username))
			if err := initNotaryRepoWithSigners(notaryRepo, userRole); err != nil {
				return trust.NotaryError(imgRefAndAuth.Reference().Name(), err)
			}

			fmt.Fprintf(cli.Out(), "Created signer: %s\n", imgRefAndAuth.AuthConfig().Username)
			fmt.Fprintf(cli.Out(), "Finished initializing signed repository for %s\n", imageName)
		default:
			return trust.NotaryError(imgRefAndAuth.RepoInfo().Name.Name(), err)
		}
	}
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(cli, imgRefAndAuth.RepoInfo().Index, "push")
	target, err := createTarget(notaryRepo, tag)
	if err != nil || options.local {
		switch err := err.(type) {
		// If the error is nil then the local flag is set
		case client.ErrNoSuchTarget, client.ErrRepositoryNotExist, nil:
			// Fail fast if the image doesn't exist locally
			if err := checkLocalImageExistence(ctx, cli, imageName); err != nil {
				return err
			}
			fmt.Fprintf(cli.Out(), "Signing and pushing trust data for local image %s, may overwrite remote trust data\n", imageName)
			return image.TrustedPush(ctx, cli, imgRefAndAuth.RepoInfo(), imgRefAndAuth.Reference(), *imgRefAndAuth.AuthConfig(), requestPrivilege)
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
		return errors.Wrapf(err, "failed to sign %q:%s", imgRefAndAuth.RepoInfo().Name.Name(), tag)
	}
	fmt.Fprintf(cli.Out(), "Successfully signed %q:%s\n", imgRefAndAuth.RepoInfo().Name.Name(), tag)
	return nil
}

func checkLocalImageExistence(ctx context.Context, cli command.Cli, imageName string) error {
	_, _, err := cli.Client().ImageInspectWithRaw(ctx, imageName)
	return err
}

func createTarget(notaryRepo client.Repository, tag string) (client.Target, error) {
	target := &client.Target{}
	var err error
	if tag == "" {
		return *target, fmt.Errorf("No tag specified")
	}
	target.Name = tag
	target.Hashes, target.Length, err = getSignedManifestHashAndSize(notaryRepo, tag)
	return *target, err
}

func getSignedManifestHashAndSize(notaryRepo client.Repository, tag string) (data.Hashes, int64, error) {
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

func getExistingSignatureInfoForReleasedTag(notaryRepo client.Repository, tag string) (trustTagRow, error) {
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

func initNotaryRepoWithSigners(notaryRepo client.Repository, newSigner data.RoleName) error {
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

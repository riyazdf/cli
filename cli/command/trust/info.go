package trust

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
)

const releasedRoleName = "owner"

type trustTagKey struct {
	TagName string
	HashHex string
}

type trustTagRow struct {
	trustTagKey
	Signers []string
}

type trustTagRowList []trustTagRow

func (tagComparator trustTagRowList) Len() int {
	return len(tagComparator)
}

func (tagComparator trustTagRowList) Less(i, j int) bool {
	return tagComparator[i].TagName < tagComparator[j].TagName
}

func (tagComparator trustTagRowList) Swap(i, j int) {
	tagComparator[i], tagComparator[j] = tagComparator[j], tagComparator[i]
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
		return trust.NotaryError(ref.Name(), err)
	}

	// Retrieve all released signatures, match them, and pretty print them
	allSignedTargets, err := notaryRepo.GetAllTargetMetadataByName("")
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	signatureRows, err := matchReleasedSignatures(allSignedTargets)
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}
	printSignatures(cli, remote, signatureRows)

	return nil
}

// aggregate all signers for a "released" hash+tagname pair. To be "released," the tag must have been
// signed into the "targets" or "targets/releases" role. Output is sorted by tag name
func matchReleasedSignatures(allTargets []client.TargetSignedStruct) ([]trustTagRow, error) {
	signatureRows := trustTagRowList{}
	// do a first pass to get filter on tags signed into "targets" or "targets/releases"
	releasedTargetRows := map[trustTagKey][]string{}
	for _, tgt := range allTargets {
		if isReleasedTarget(tgt.Role.Name) {
			releasedKey := trustTagKey{tgt.Target.Name, hex.EncodeToString(tgt.Target.Hashes[notary.SHA256])}
			releasedTargetRows[releasedKey] = []string{}
		}
	}

	// now fill out all signers on released keys
	for _, tgt := range allTargets {
		targetKey := trustTagKey{tgt.Target.Name, hex.EncodeToString(tgt.Target.Hashes[notary.SHA256])}
		// only considered released targets
		if _, ok := releasedTargetRows[targetKey]; ok && !isReleasedTarget(tgt.Role.Name) {
			releasedTargetRows[targetKey] = append(releasedTargetRows[targetKey], notaryRoleToSigner(tgt.Role.Name))
		}
	}

	// compile the final output as a sorted slice
	for targetKey, signers := range releasedTargetRows {
		signatureRows = append(signatureRows, trustTagRow{targetKey, signers})
	}
	sort.Sort(signatureRows)
	if len(signatureRows) == 0 {
		return nil, fmt.Errorf("no signatures for image")
	}
	return signatureRows, nil
}

// TODO(riyazdf): pretty print with ordered rows
func printSignatures(cli command.Cli, imageName string, signatureRows []trustTagRow) {
	fmt.Fprintf(cli.Out(), "SIGNATURE DATA FOR %s:\n\n", imageName)
	for _, sigRow := range signatureRows {
		fmt.Fprintf(cli.Out(), "%s\t%s\t\t%s\n", sigRow.TagName, sigRow.HashHex, sigRow.Signers)
	}
}

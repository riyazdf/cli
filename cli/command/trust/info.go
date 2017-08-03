package trust

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/formatter"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
)

const releasedRoleName = "admin"

// trustTagKey represents a unique signed tag and hex-encoded hash pair
type trustTagKey struct {
	TagName string
	HashHex string
}

// trustTagRow encodes all human-consumable information for a signed tag, including signers
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
	ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, remote)
	if err != nil {
		return err
	}

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, *authConfig, "pull")
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
	if err := printSignatures(cli, signatureRows); err != nil {
		return err
	}

	roleWithSigs, err := notaryRepo.ListRoles()
	if err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	signerRoleToKeyIDs, adminRoleToKeyIDs := getSignerAndAdminRolesWithKeyIDs(roleWithSigs)
	// If we do not have additional signers, do not display
	if len(signerRoleToKeyIDs) > 0 {
		fmt.Fprintf(cli.Out(), "\nList of signers and their KeyIDs:\n\n")
		printSignerInfo(cli, signerRoleToKeyIDs)
	}

	// This will always have the root and targets information
	fmt.Fprintf(cli.Out(), "\nList of admins and their KeyIDs:\n\n")
	printSignerInfo(cli, adminRoleToKeyIDs)

	return nil
}

// Extract signer keys and admin keys from the list of roles
func getSignerAndAdminRolesWithKeyIDs(roleWithSigs []client.RoleWithSignatures) (map[string][]string, map[string][]string) {
	signerRoleToKeyIDs := make(map[string][]string)
	adminRoleToKeyIDs := make(map[string][]string)

	for _, roleWithSig := range roleWithSigs {
		switch roleWithSig.Name {
		case trust.ReleasesRole, data.CanonicalSnapshotRole, data.CanonicalTimestampRole:
			continue
		case data.CanonicalRootRole, data.CanonicalTargetsRole:
			adminRoleToKeyIDs[notaryRoleToSigner(roleWithSig.Name)] = roleWithSig.KeyIDs
		default:
			signerRoleToKeyIDs[notaryRoleToSigner(roleWithSig.Name)] = roleWithSig.KeyIDs
		}
	}
	return signerRoleToKeyIDs, adminRoleToKeyIDs
}

// aggregate all signers for a "released" hash+tagname pair. To be "released," the tag must have been
// signed into the "targets" or "targets/releases" role. Output is sorted by tag name
func matchReleasedSignatures(allTargets []client.TargetSignedStruct) (trustTagRowList, error) {
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

// pretty print with ordered rows
func printSignatures(dockerCli command.Cli, signatureRows trustTagRowList) error {
	trustTagCtx := formatter.Context{
		Output: dockerCli.Out(),
		Format: formatter.NewTrustTagFormat(),
	}
	// convert the formatted type before printing
	formattedTags := []formatter.SignedTagInfo{}
	for _, sigRow := range signatureRows {
		formattedTags = append(formattedTags, formatter.SignedTagInfo{
			Name:    sigRow.TagName,
			Digest:  sigRow.HashHex,
			Signers: sigRow.Signers,
		})
	}
	return formatter.TrustTagWrite(trustTagCtx, formattedTags)
}

func printSignerInfo(dockerCli command.Cli, roleToKeyIDs map[string][]string) error {
	signerInfoCtx := formatter.Context{
		Output: dockerCli.Out(),
		Format: formatter.NewSignerInfoFormat(),
		Trunc:  true,
	}
	formattedSignerInfo := formatter.SignerInfoList{}
	for name, keyIDs := range roleToKeyIDs {
		formattedSignerInfo = append(formattedSignerInfo, formatter.SignerInfo{
			Name: name,
			Keys: keyIDs,
		})
	}
	sort.Sort(formattedSignerInfo)
	return formatter.SignerInfoWrite(signerInfoCtx, formattedSignerInfo)
}

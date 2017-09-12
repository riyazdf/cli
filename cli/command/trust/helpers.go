package trust

import (
	"sort"
	"strings"

	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
)

const releasedRoleName = "Repo Admin"
const releasesRoleTUFName = "targets/releases"

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

func clearChangeList(notaryRepo client.Repository) error {
	cl, err := notaryRepo.GetChangelist()
	if err != nil {
		return err
	}
	return cl.Clear("")
}

// generates an ECDSA key without a GUN for the specified role
func getOrGenerateNotaryKey(notaryRepo *client.NotaryRepository, role data.RoleName) (data.PublicKey, error) {
	// use the signer name in the PEM headers if this is a delegation key
	if data.IsDelegation(role) {
		role = data.RoleName(notaryRoleToSigner(role))
	}
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

func getOrGenerateRootKeyAndInitRepo(notaryRepo *client.NotaryRepository) error {
	rootKey, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	if err != nil {
		return err
	}
	// Initialize the notary repository with a remotely managed snapshot
	// key
	return notaryRepo.Initialize([]string{rootKey.ID()}, data.CanonicalSnapshotRole)
}

package trust

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/client/changelist"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf/data"

	"github.com/stretchr/testify/assert"
)

func TestGetOrGenerateNotaryKey(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)

	// repo is empty, try making a root key
	rootKeyA, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	assert.NoError(t, err)
	assert.NotNil(t, rootKeyA)

	// we should only have one newly generated key
	allKeys := notaryRepo.GetCryptoService().ListAllKeys()
	assert.Len(t, allKeys, 1)
	assert.NotNil(t, notaryRepo.GetCryptoService().GetKey(rootKeyA.ID()))

	// this time we should get back the same key if we ask for another root key
	rootKeyB, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	assert.NoError(t, err)
	assert.NotNil(t, rootKeyB)

	// we should only have one newly generated key
	allKeys = notaryRepo.GetCryptoService().ListAllKeys()
	assert.Len(t, allKeys, 1)
	assert.NotNil(t, notaryRepo.GetCryptoService().GetKey(rootKeyB.ID()))

	// The key we retrieved should be identical to the one we generated
	assert.Equal(t, rootKeyA, rootKeyB)

	// Now also try with a delegation key
	releasesKey, err := getOrGenerateNotaryKey(notaryRepo, data.RoleName(trust.ReleasesRole))
	assert.NoError(t, err)
	assert.NotNil(t, releasesKey)

	// we should now have two keys
	allKeys = notaryRepo.GetCryptoService().ListAllKeys()
	assert.Len(t, allKeys, 2)
	assert.NotNil(t, notaryRepo.GetCryptoService().GetKey(releasesKey.ID()))
	// The key we retrieved should be identical to the one we generated
	assert.NotEqual(t, releasesKey, rootKeyA)
	assert.NotEqual(t, releasesKey, rootKeyB)
}

func TestGetOrGenerateNotaryKeyAndInitRepo(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)

	err = getOrGenerateRootKeyAndInitRepo(notaryRepo)
	assert.EqualError(t, err, "client is offline")
}

func TestAddStageSigners(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)

	// stage targets/user
	userRole := data.RoleName("targets/user")
	userKey := data.NewPublicKey("algoA", []byte("a"))
	addStagedSigner(notaryRepo, userRole, []data.PublicKey{userKey})
	// check the changelist for four total changes: two on targets/releases and two on targets/user
	cl, err := notaryRepo.GetChangelist()
	assert.NoError(t, err)
	changeList := cl.List()
	assert.Len(t, changeList, 4)
	// ordering is determinstic:

	// first change is for targets/user key creation
	newSignerKeyChange := changeList[0]
	expectedJSON, err := json.Marshal(&changelist.TUFDelegation{
		NewThreshold: notary.MinThreshold,
		AddKeys:      data.KeyList([]data.PublicKey{userKey}),
	})
	expectedChange := changelist.NewTUFChange(
		changelist.ActionCreate,
		userRole,
		changelist.TypeTargetsDelegation,
		"", // no path for delegations
		expectedJSON,
	)
	assert.Equal(t, expectedChange, newSignerKeyChange)

	// second change is for targets/user getting all paths
	newSignerPathsChange := changeList[1]
	expectedJSON, err = json.Marshal(&changelist.TUFDelegation{
		AddPaths: []string{""},
	})
	expectedChange = changelist.NewTUFChange(
		changelist.ActionCreate,
		userRole,
		changelist.TypeTargetsDelegation,
		"", // no path for delegations
		expectedJSON,
	)
	assert.Equal(t, expectedChange, newSignerPathsChange)

	releasesRole := data.RoleName("targets/releases")

	// third change is for targets/releases key creation
	releasesKeyChange := changeList[2]
	expectedJSON, err = json.Marshal(&changelist.TUFDelegation{
		NewThreshold: notary.MinThreshold,
		AddKeys:      data.KeyList([]data.PublicKey{userKey}),
	})
	expectedChange = changelist.NewTUFChange(
		changelist.ActionCreate,
		releasesRole,
		changelist.TypeTargetsDelegation,
		"", // no path for delegations
		expectedJSON,
	)
	assert.Equal(t, expectedChange, releasesKeyChange)

	// fourth change is for targets/releases getting all paths
	releasesPathsChange := changeList[3]
	expectedJSON, err = json.Marshal(&changelist.TUFDelegation{
		AddPaths: []string{""},
	})
	expectedChange = changelist.NewTUFChange(
		changelist.ActionCreate,
		releasesRole,
		changelist.TypeTargetsDelegation,
		"", // no path for delegations
		expectedJSON,
	)
	assert.Equal(t, expectedChange, releasesPathsChange)
}

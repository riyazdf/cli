package trust

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/notary"
	"github.com/docker/notary/client/changelist"
	"github.com/docker/notary/tuf/data"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/docker/pkg/testutil"
	"github.com/docker/notary/client"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustpinning"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires exactly 2 argument(s)",
		}, {
			name:          "still-not-enough-args",
			args:          []string{"image"},
			expectedError: "requires exactly 2 argument(s)",
		},
		{
			name:          "too-many-args",
			args:          []string{"image", "tag", "blah"},
			expectedError: "requires exactly 2 argument(s)",
		},
		{
			name:          "sha-reference",
			args:          []string{"870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd", "tag"},
			expectedError: "invalid repository name",
		},
		{
			name:          "nonexistent-reg",
			args:          []string{"nonexistent-reg-name.io/image", "tag"},
			expectedError: "no such host",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"ALPINE", "latest"},
			expectedError: "invalid reference format",
		},
		{
			name:          "no-shell-for-passwd",
			args:          []string{"riyaz/unsigned-img", "latest"},
			expectedError: "maximum number of passphrase attempts exceeded",
		},
	}
	for _, tc := range testCases {
		buf := new(bytes.Buffer)
		cmd := newSignCommand(
			test.NewFakeCliWithOutput(&fakeClient{}, buf))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

func TestGetOrGenerateNotaryKey(t *testing.T) {
	passwd := "password"
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedNotaryRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)

	// repo is empty, try making a root key
	rootKeyA, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	assert.NoError(t, err)
	assert.NotNil(t, rootKeyA)

	// we should only have one newly generated key
	allKeys := notaryRepo.CryptoService.ListAllKeys()
	assert.Len(t, allKeys, 1)
	assert.NotNil(t, notaryRepo.CryptoService.GetKey(rootKeyA.ID()))

	// this time we should get back the same key if we ask for another root key
	rootKeyB, err := getOrGenerateNotaryKey(notaryRepo, data.CanonicalRootRole)
	assert.NoError(t, err)
	assert.NotNil(t, rootKeyB)

	// we should only have one newly generated key
	allKeys = notaryRepo.CryptoService.ListAllKeys()
	assert.Len(t, allKeys, 1)
	assert.NotNil(t, notaryRepo.CryptoService.GetKey(rootKeyB.ID()))

	// The key we retrieved should be identical to the one we generated
	assert.Equal(t, rootKeyA, rootKeyB)

	// Now also try with a delegation key
	releasesKey, err := getOrGenerateNotaryKey(notaryRepo, data.RoleName(trust.ReleasesRole))
	assert.NoError(t, err)
	assert.NotNil(t, releasesKey)

	// we should now have two keys
	allKeys = notaryRepo.CryptoService.ListAllKeys()
	assert.Len(t, allKeys, 2)
	assert.NotNil(t, notaryRepo.CryptoService.GetKey(releasesKey.ID()))
	// The key we retrieved should be identical to the one we generated
	assert.NotEqual(t, releasesKey, rootKeyA)
	assert.NotEqual(t, releasesKey, rootKeyB)
}

func TestAddStageSigners(t *testing.T) {
	passwd := "password"
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedNotaryRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
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

package trust

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/internal/test"
	"github.com/docker/cli/internal/test/testutil"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/assert"
)

const passwd = "password"

func TestTrustSignCommandErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires exactly 1 argument",
		},
		{
			name:          "too-many-args",
			args:          []string{"image", "tag"},
			expectedError: "requires exactly 1 argument",
		},
		{
			name:          "sha-reference",
			args:          []string{"870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd"},
			expectedError: "invalid repository name",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"ALPINE:latest"},
			expectedError: "invalid reference format",
		},
		{
			name:          "no-tag",
			args:          []string{"reg/img"},
			expectedError: "No tag specified for reg/img",
		},
		{
			name:          "digest-reference",
			args:          []string{"ubuntu@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2"},
			expectedError: "cannot use a digest reference for IMAGE:TAG",
		},
	}
	// change to a tmpdir
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)
	for _, tc := range testCases {
		cmd := newSignCommand(
			test.NewFakeCli(&fakeClient{}))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

func TestTrustSignCommandOfflineErrors(t *testing.T) {
	cli := test.NewFakeCli(&fakeClient{})
	cli.SetNotaryClient(getOfflineNotaryRepository)
	cmd := newSignCommand(cli)
	cmd.SetArgs([]string{"reg-name.io/image:tag"})
	cmd.SetOutput(ioutil.Discard)
	assert.Error(t, cmd.Execute())
	testutil.ErrorContains(t, cmd.Execute(), "client is offline")
}

func TestGetSignedManifestHashAndSize(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)
	target := &client.Target{}
	target.Hashes, target.Length, err = getSignedManifestHashAndSize(notaryRepo, "test")
	assert.EqualError(t, err, "client is offline")
}

func TestGetReleasedTargetHashAndSize(t *testing.T) {
	oneReleasedTgt := []client.TargetSignedStruct{}
	// make and append 3 non-released signatures on the "unreleased" target
	unreleasedTgt := client.Target{Name: "unreleased", Hashes: data.Hashes{notary.SHA256: []byte("hash")}}
	for _, unreleasedRole := range []string{"targets/a", "targets/b", "targets/c"} {
		oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName(unreleasedRole), Target: unreleasedTgt})
	}
	_, _, err := getReleasedTargetHashAndSize(oneReleasedTgt, "unreleased")
	assert.EqualError(t, err, "No valid trust data for unreleased")
	releasedTgt := client.Target{Name: "released", Hashes: data.Hashes{notary.SHA256: []byte("released-hash")}}
	oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: releasedTgt})
	hash, _, _ := getReleasedTargetHashAndSize(oneReleasedTgt, "unreleased")
	assert.Equal(t, data.Hashes{notary.SHA256: []byte("released-hash")}, hash)

}

func TestCreateTarget(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)
	_, err = createTarget(notaryRepo, "")
	assert.EqualError(t, err, "No tag specified")
	_, err = createTarget(notaryRepo, "1")
	assert.EqualError(t, err, "client is offline")
}

func TestGetExistingSignatureInfoForReleasedTag(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "gun", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)
	_, err = getExistingSignatureInfoForReleasedTag(notaryRepo, "test")
	assert.EqualError(t, err, "client is offline")
}

func TestPrettyPrintExistingSignatureInfo(t *testing.T) {
	fakeCli := test.NewFakeCli(&fakeClient{})

	signers := []string{"Bob", "Alice", "Carol"}
	existingSig := trustTagRow{trustTagKey{"tagName", "abc123"}, signers}
	prettyPrintExistingSignatureInfo(fakeCli, existingSig)

	assert.Contains(t, fakeCli.OutBuffer().String(), "Existing signatures for tag tagName digest abc123 from:\nAlice, Bob, Carol")
}

func TestChangeList(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)
	cmd := newSignCommand(
		test.NewFakeCli(&fakeClient{}))
	cmd.SetArgs([]string{"ubuntu:latest"})
	cmd.SetOutput(ioutil.Discard)
	err = cmd.Execute()
	notaryRepo, err := client.NewFileCachedRepository(tmpDir, "docker.io/library/ubuntu", "https://localhost", nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)
	cl, err := notaryRepo.GetChangelist()
	assert.Equal(t, len(cl.List()), 0)
}

func TestLocalFlag(t *testing.T) {
	cli := test.NewFakeCli(&fakeClient{})
	cli.SetNotaryClient(getEmptyTargetsNotaryRepository)
	cmd := newSignCommand(cli)
	cmd.SetArgs([]string{"--local", "reg-name.io/image:red"})
	cmd.SetOutput(ioutil.Discard)
	testutil.ErrorContains(t, cmd.Execute(), "error during connect: Get /images/reg-name.io/image:red/json: unsupported protocol scheme")

}

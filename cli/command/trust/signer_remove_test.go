package trust

import (
	"io/ioutil"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/docker/pkg/testutil"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignerRemoveErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args-0",
			expectedError: "requires at least 2 arguments",
		},
		{
			name:          "not-enough-args-1",
			args:          []string{"user"},
			expectedError: "requires at least 2 arguments",
		},
	}
	for _, tc := range testCases {
		cmd := newSignerRemoveCommand(
			test.NewFakeCli(&fakeClient{}))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
	testCasesWithOutput := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-an-image",
			args:          []string{"user", "notanimage"},
			expectedError: "Error retrieving signers for notanimage",
		},
		{
			name:          "sha-reference",
			args:          []string{"user", "870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd"},
			expectedError: "invalid repository name",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"user", "ALPINE"},
			expectedError: "invalid reference format",
		},
	}
	for _, tc := range testCasesWithOutput {
		cli := test.NewFakeCli(&fakeClient{})
		cmd := newSignerRemoveCommand(cli)
		cmd.SetArgs(tc.args)
		cmd.Execute()
		assert.Contains(t, cli.OutBuffer().String(), tc.expectedError)
	}

}

func TestRemoveSingleSigner(t *testing.T) {
	cli := test.NewFakeCli(&fakeClient{})
	err := removeSingleSigner(cli, "eiais/test2", "test", true)
	assert.EqualError(t, err, "No signer test for image eiais/test2")
	assert.Contains(t, cli.OutBuffer().String(), "\nRemoving signer \"test\" from eiais/test2...\n")
	err = removeSingleSigner(cli, "eiais/test2", "releases", true)
	assert.EqualError(t, err, "releases is a reserved keyword and cannot be removed")
	assert.Contains(t, cli.OutBuffer().String(), "\nRemoving signer \"releases\" from eiais/test2...\n")
}

func TestRemoveMultipleSigners(t *testing.T) {
	cli := test.NewFakeCli(&fakeClient{})
	err := removeSigner(cli, "test", []string{"repo1", "repo2"}, &signerRemoveOptions{forceYes: true})
	assert.EqualError(t, err, "Error removing signer from: repo1, repo2")
	assert.Contains(t, cli.OutBuffer().String(),
		"\nRemoving signer \"test\" from repo1...\nError retrieving signers for repo1\n\nRemoving signer \"test\" from repo2...\nError retrieving signers for repo2")
}

func TestIsLastSignerForReleases(t *testing.T) {
	role := data.Role{}
	releaserole := client.RoleWithSignatures{}
	releaserole.Name = releasesRoleTUFName
	releaserole.Threshold = 1
	allrole := []client.RoleWithSignatures{releaserole}
	lastsigner, _ := isLastSignerForReleases(role, allrole)
	assert.Equal(t, false, lastsigner)

	role.KeyIDs = []string{"deadbeef"}
	sig := data.Signature{}
	sig.KeyID = "deadbeef"
	releaserole.Signatures = []data.Signature{sig}
	releaserole.Threshold = 1
	allrole = []client.RoleWithSignatures{releaserole}
	lastsigner, _ = isLastSignerForReleases(role, allrole)
	assert.Equal(t, true, lastsigner)

	sig.KeyID = "8badf00d"
	releaserole.Signatures = []data.Signature{sig}
	releaserole.Threshold = 1
	allrole = []client.RoleWithSignatures{releaserole}
	lastsigner, _ = isLastSignerForReleases(role, allrole)
	assert.Equal(t, false, lastsigner)

}

package trust

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/testutil"
	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/assert"
)

type fakeClient struct {
	client.Client
}

func TestTrustInfoErrors(t *testing.T) {
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
			args:          []string{"remote1", "remote2"},
			expectedError: "requires exactly 1 argument",
		},
		{
			name:          "sha-reference",
			args:          []string{"870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd"},
			expectedError: "invalid repository name",
		},
		{
			name:          "nonexistent-reg",
			args:          []string{"nonexistent-reg-name.io/image"},
			expectedError: "no such host",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"ALPINE"},
			expectedError: "invalid reference format",
		},
		{
			name:          "unsigned-img-reference",
			args:          []string{"riyaz/unsigned-img"},
			expectedError: "notary.docker.io does not have trust data for docker.io/riyaz/unsigned-img",
		},
		{
			name:          "nonexistent-img-reference",
			args:          []string{"riyaz/nonexistent-img"},
			expectedError: "you are not authorized to perform this operation: server returned 401",
		},
	}
	for _, tc := range testCases {
		buf := new(bytes.Buffer)
		cmd := newInfoCommand(
			test.NewFakeCliWithOutput(&fakeClient{}, buf))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

func TestTrustInfo(t *testing.T) {
	buf := new(bytes.Buffer)
	cmd := newInfoCommand(
		test.NewFakeCliWithOutput(&fakeClient{}, buf))
	cmd.SetArgs([]string{"alpine"})
	assert.NoError(t, cmd.Execute())
}

func TestTUFToSigner(t *testing.T) {
	assert.Equal(t, releasedRoleName, notaryRoleToSigner(data.CanonicalTargetsRole))
	assert.Equal(t, releasedRoleName, notaryRoleToSigner(trust.ReleasesRole))
	assert.Equal(t, "signer", notaryRoleToSigner("targets/signer"))
	assert.Equal(t, "docker/signer", notaryRoleToSigner("targets/docker/signer"))

	// It's nonsense for other base roles to have signed off on a target, but this function leaves role names intact
	for _, role := range data.BaseRoles {
		if role == data.CanonicalTargetsRole {
			continue
		}
		assert.Equal(t, role.String(), notaryRoleToSigner(role))
	}
	assert.Equal(t, "notarole", notaryRoleToSigner(data.RoleName("notarole")))
}

// check if a role name is "released": either targets/releases or targets TUF roles
func TestIsReleasedTarget(t *testing.T) {
	assert.True(t, isReleasedTarget(trust.ReleasesRole))
	for _, role := range data.BaseRoles {
		assert.Equal(t, role == data.CanonicalTargetsRole, isReleasedTarget(role))
	}
	assert.False(t, isReleasedTarget(data.RoleName("targets/not-releases")))
	assert.False(t, isReleasedTarget(data.RoleName("random")))
	assert.False(t, isReleasedTarget(data.RoleName("targets/releases/subrole")))
}

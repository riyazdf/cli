package trust

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/cli/cli/trust"
	dockerClient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/testutil"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/assert"
)

type fakeClient struct {
	dockerClient.Client
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

// creates a mock delegation with a given name and no keys
func mockDelegationRoleWithName(name string) data.DelegationRole {
	baseRole := data.NewBaseRole(
		data.RoleName(name),
		notary.MinThreshold,
	)
	return data.DelegationRole{baseRole, []string{}}
}

func TestMatchEmptySignatures(t *testing.T) {
	// first try empty targets
	emptyTgts := []client.TargetSignedStruct{}

	matchedSigRows, err := matchReleasedSignatures(emptyTgts)
	assert.Error(t, err)
	assert.Empty(t, matchedSigRows)
}

func TestMatchUnreleasedSignatures(t *testing.T) {
	// try an "unreleased" target with 3 signatures, 0 rows will appear
	unreleasedTgts := []client.TargetSignedStruct{}

	tgt := client.Target{Name: "unreleased", Hashes: data.Hashes{notary.SHA256: []byte("hash")}}
	for _, unreleasedRole := range []string{"targets/a", "targets/b", "targets/c"} {
		unreleasedTgts = append(unreleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName(unreleasedRole), Target: tgt})
	}

	matchedSigRows, err := matchReleasedSignatures(unreleasedTgts)
	assert.Error(t, err)
	assert.Empty(t, matchedSigRows)
}

func TestMatchOneReleasedSingleSignature(t *testing.T) {
	// now try only 1 "released" target with no additional sigs, 1 row will appear with 0 signers
	oneReleasedTgt := []client.TargetSignedStruct{}

	// make and append the "released" target to our mock input
	releasedTgt := client.Target{Name: "released", Hashes: data.Hashes{notary.SHA256: []byte("released-hash")}}
	oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: releasedTgt})

	// make and append 3 non-released signatures on the "unreleased" target
	unreleasedTgt := client.Target{Name: "unreleased", Hashes: data.Hashes{notary.SHA256: []byte("hash")}}
	for _, unreleasedRole := range []string{"targets/a", "targets/b", "targets/c"} {
		oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName(unreleasedRole), Target: unreleasedTgt})
	}

	matchedSigRows, err := matchReleasedSignatures(oneReleasedTgt)
	assert.NoError(t, err)
	assert.Len(t, matchedSigRows, 1)

	outputRow := matchedSigRows[0]
	// Empty signers because "targets/releases" doesn't show up
	assert.Empty(t, outputRow.Signers)
	assert.Equal(t, releasedTgt.Name, outputRow.TagName)
	assert.Equal(t, hex.EncodeToString(releasedTgt.Hashes[notary.SHA256]), outputRow.HashHex)
}

func TestMatchOneReleasedMultiSignature(t *testing.T) {
	// now try only 1 "released" target with 3 additional sigs, 1 row will appear with 3 signers
	oneReleasedTgt := []client.TargetSignedStruct{}

	// make and append the "released" target to our mock input
	releasedTgt := client.Target{Name: "released", Hashes: data.Hashes{notary.SHA256: []byte("released-hash")}}
	oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: releasedTgt})

	// make and append 3 non-released signatures on both the "released" and "unreleased" targets
	unreleasedTgt := client.Target{Name: "unreleased", Hashes: data.Hashes{notary.SHA256: []byte("hash")}}
	for _, unreleasedRole := range []string{"targets/a", "targets/b", "targets/c"} {
		oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName(unreleasedRole), Target: unreleasedTgt})
		oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName(unreleasedRole), Target: releasedTgt})
	}

	matchedSigRows, err := matchReleasedSignatures(oneReleasedTgt)
	assert.NoError(t, err)
	assert.Len(t, matchedSigRows, 1)

	outputRow := matchedSigRows[0]
	// We should have three signers
	assert.Equal(t, outputRow.Signers, []string{"a", "b", "c"})
	assert.Equal(t, releasedTgt.Name, outputRow.TagName)
	assert.Equal(t, hex.EncodeToString(releasedTgt.Hashes[notary.SHA256]), outputRow.HashHex)
}

func TestMatchMultiReleasedMultiSignature(t *testing.T) {
	// now try 3 "released" targets with additional sigs to show 3 rows as follows:
	// target-a is signed by targets/releases and targets/a - a will be the signer
	// target-b is signed by targets/releases, targets/a, targets/b - a and b will be the signers
	// target-c is signed by targets/releases, targets/a, targets/b, targets/c - a, b, and c will be the signers
	multiReleasedTgts := []client.TargetSignedStruct{}
	// make target-a, target-b, and target-c
	targetA := client.Target{Name: "target-a", Hashes: data.Hashes{notary.SHA256: []byte("target-a-hash")}}
	targetB := client.Target{Name: "target-b", Hashes: data.Hashes{notary.SHA256: []byte("target-b-hash")}}
	targetC := client.Target{Name: "target-c", Hashes: data.Hashes{notary.SHA256: []byte("target-c-hash")}}

	// have targets/releases "sign" on all of these targets so they are released
	multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: targetA})
	multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: targetB})
	multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/releases"), Target: targetC})

	// targets/a signs off on all three targets (target-a, target-b, target-c):
	for _, tgt := range []client.Target{targetA, targetB, targetC} {
		multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/a"), Target: tgt})
	}

	// targets/b signs off on the final two targets (target-b, target-c):
	for _, tgt := range []client.Target{targetB, targetC} {
		multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/b"), Target: tgt})
	}

	// targets/c only signs off on the last target (target-c):
	multiReleasedTgts = append(multiReleasedTgts, client.TargetSignedStruct{Role: mockDelegationRoleWithName("targets/c"), Target: targetC})

	matchedSigRows, err := matchReleasedSignatures(multiReleasedTgts)
	assert.NoError(t, err)
	assert.Len(t, matchedSigRows, 3)

	// note that the output is sorted by tag name, so we can reliably index to validate data:
	outputTargetA := matchedSigRows[0]
	assert.Equal(t, outputTargetA.Signers, []string{"a"})
	assert.Equal(t, targetA.Name, outputTargetA.TagName)
	assert.Equal(t, hex.EncodeToString(targetA.Hashes[notary.SHA256]), outputTargetA.HashHex)

	outputTargetB := matchedSigRows[1]
	assert.Equal(t, outputTargetB.Signers, []string{"a", "b"})
	assert.Equal(t, targetB.Name, outputTargetB.TagName)
	assert.Equal(t, hex.EncodeToString(targetB.Hashes[notary.SHA256]), outputTargetB.HashHex)

	outputTargetC := matchedSigRows[2]
	assert.Equal(t, outputTargetC.Signers, []string{"a", "b", "c"})
	assert.Equal(t, targetC.Name, outputTargetC.TagName)
	assert.Equal(t, hex.EncodeToString(targetC.Hashes[notary.SHA256]), outputTargetC.HashHex)
}

func TestMatchReleasedSignatureFromTargets(t *testing.T) {
	// now try only 1 "released" target with no additional sigs, one rows will appear
	oneReleasedTgt := []client.TargetSignedStruct{}
	// make and append the "released" target to our mock input
	releasedTgt := client.Target{Name: "released", Hashes: data.Hashes{notary.SHA256: []byte("released-hash")}}
	oneReleasedTgt = append(oneReleasedTgt, client.TargetSignedStruct{Role: mockDelegationRoleWithName(data.CanonicalTargetsRole.String()), Target: releasedTgt})
	matchedSigRows, err := matchReleasedSignatures(oneReleasedTgt)
	assert.NoError(t, err)
	assert.Len(t, matchedSigRows, 1)
	outputRow := matchedSigRows[0]
	// Empty signers because "targets" doesn't show up
	assert.Empty(t, outputRow.Signers)
	assert.Equal(t, releasedTgt.Name, outputRow.TagName)
	assert.Equal(t, hex.EncodeToString(releasedTgt.Hashes[notary.SHA256]), outputRow.HashHex)
}

func TestGetSignerAndBaseRolesWithKeyIDs(t *testing.T) {
	roles := []data.Role{
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key11"},
			},
			Name: "targets/alice",
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key21", "key22"},
			},
			Name: "targets/releases",
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key31"},
			},
			Name: data.CanonicalRootRole,
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key41"},
			},
			Name: data.CanonicalTargetsRole,
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key51"},
			},
			Name: data.CanonicalSnapshotRole,
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key61"},
			},
			Name: data.CanonicalTimestampRole,
		},
		{
			RootRole: data.RootRole{
				KeyIDs: []string{"key71", "key72"},
			},
			Name: "targets/bob",
		},
	}
	expectedSignerRoleToKeyIDs := map[string][]string{
		"alice": {"key11"},
		"bob":   {"key71", "key72"},
	}
	expectedBaseRoleToKeyIDs := map[string][]string{
		"root":  {"key31"},
		"admin": {"key41"},
	}

	var roleWithSigs []client.RoleWithSignatures
	for _, role := range roles {
		roleWithSig := client.RoleWithSignatures{Role: role, Signatures: nil}
		roleWithSigs = append(roleWithSigs, roleWithSig)
	}
	signerRoleToKeyIDs, baseRoleToKeyIDs := getSignerAndBaseRolesWithKeyIDs(roleWithSigs)
	assert.Equal(t, signerRoleToKeyIDs, expectedSignerRoleToKeyIDs)
	assert.Equal(t, baseRoleToKeyIDs, expectedBaseRoleToKeyIDs)
}
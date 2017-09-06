package trust

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/docker/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignerAddErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires at least 2 argument",
		},
		{
			name:          "no-key",
			args:          []string{"foo", "bar"},
			expectedError: "path to a valid public key must be provided using the `--key` flag",
		},
		{
			name:          "reserved-releases-signer-add",
			args:          []string{"releases", "my-image", "-k", "/path/to/key"},
			expectedError: "releases is a reserved keyword, please use a different signer name",
		},
	}
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)

	for _, tc := range testCases {
		cmd := newSignerAddCommand(
			test.NewFakeCli(&fakeClient{}))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

func TestSignerAddCommandNoTargetsKey(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)

	tmpfile, err := ioutil.TempFile("", "pemfile")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	cli := test.NewFakeCli(&fakeClient{})
	cmd := newSignerAddCommand(cli)
	cmd.SetArgs([]string{"--key", tmpfile.Name(), "alice", "alpine", "linuxkit/alpine"})

	assert.NoError(t, cmd.Execute())

	assert.Contains(t, cli.OutBuffer().String(), "Adding signer \"alice\" to alpine...")
	assert.Contains(t, cli.OutBuffer().String(), "Failed to add signer to alpine: no valid public key found")

	assert.Contains(t, cli.OutBuffer().String(), "Adding signer \"alice\" to linuxkit/alpine...")
	assert.Contains(t, cli.OutBuffer().String(), "Failed to add signer to linuxkit/alpine: no valid public key found")
}

func TestSignerAddCommandBadKeyPath(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)

	cli := test.NewFakeCli(&fakeClient{})
	cmd := newSignerAddCommand(cli)
	cmd.SetArgs([]string{"--key", "/path/to/key.pem", "alice", "alpine"})

	assert.NoError(t, cmd.Execute())

	expectedError := "\nAdding signer \"alice\" to alpine...\nFailed to add signer to alpine: file for public key does not exist: /path/to/key.pem"
	assert.Contains(t, cli.OutBuffer().String(), expectedError)
}

func TestSignerAddCommandInvalidRepoName(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "docker-sign-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)

	cli := test.NewFakeCli(&fakeClient{})
	cmd := newSignerAddCommand(cli)
	imageName := "870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd"
	cmd.SetArgs([]string{"--key", "/path/to/key.pem", "alice", imageName})

	assert.NoError(t, cmd.Execute())

	expectedError := fmt.Sprintf("Failed to add signer to %s: invalid repository name (%s), cannot specify 64-byte hexadecimal strings\n", imageName, imageName)
	assert.Equal(t, expectedError, cli.OutBuffer().String())
}

func TestIngestPublicKeys(t *testing.T) {
	// Call with a bad path
	_, err := ingestPublicKeys([]string{"foo", "bar"})
	assert.EqualError(t, err, "file for public key does not exist: foo")
	// Call with real file path
	tmpfile, err := ioutil.TempFile("", "pemfile")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	_, err = ingestPublicKeys([]string{tmpfile.Name()})
	assert.EqualError(t, err, "no valid public key found")
}

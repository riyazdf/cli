package trust

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/docker/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestTrustKeyLoadErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires at least 1 argument",
		},
		{
			name:          "not-a-key",
			args:          []string{"iamnotakey"},
			expectedError: "no such file or directory",
		},
	}
	tmpDir, err := ioutil.TempDir("", "docker-key-load-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	config.SetDir(tmpDir)

	for _, tc := range testCases {
		cmd := newKeyLoadCommand(
			test.NewFakeCli(&fakeClient{}))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

package trust

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/docker/pkg/testutil"
)

func TestTrustRevokeErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires exactly 1 argument(s)",
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
			name:          "trust-data-for-tag-does-not-exist",
			args:          []string{"alpine:foo"},
			expectedError: "could not remove signature for alpine:foo: No valid trust data for foo",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"ALPINE"},
			expectedError: "invalid reference format",
		},
		{
			name: "unsigned-img-reference",
			args: []string{"riyaz/unsigned-img:v1"},
			expectedError: strings.Join([]string{
				"could not remove signature for riyaz/unsigned-img:v1:",
				"Error: remote trust data does not exist for docker.io/riyaz/unsigned-img:",
				"notary.docker.io does not have trust data for docker.io/riyaz/unsigned-img",
			}, " "),
		},
	}
	for _, tc := range testCases {
		buf := new(bytes.Buffer)
		cmd := newRevokeCommand(
			test.NewFakeCliWithOutput(&fakeClient{}, buf))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

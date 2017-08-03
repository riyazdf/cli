package trust

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	"github.com/docker/docker/pkg/testutil"
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

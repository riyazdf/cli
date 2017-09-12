package command

import (
	"os"
	"testing"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIClientFromFlags(t *testing.T) {
	host := "unix://path"
	opts := &flags.CommonOptions{Hosts: []string{host}}
	configFile := &configfile.ConfigFile{
		HTTPHeaders: map[string]string{
			"My-Header": "Custom-Value",
		},
	}
	apiclient, err := NewAPIClientFromFlags(opts, configFile)
	require.NoError(t, err)
	assert.Equal(t, host, apiclient.DaemonHost())

	expectedHeaders := map[string]string{
		"My-Header":  "Custom-Value",
		"User-Agent": UserAgent(),
	}
	assert.Equal(t, expectedHeaders, apiclient.(*client.Client).CustomHTTPHeaders())
	assert.Equal(t, api.DefaultVersion, apiclient.ClientVersion())
}

func TestNewAPIClientFromFlagsWithAPIVersionFromEnv(t *testing.T) {
	customVersion := "v3.3.3"
	defer patchEnvVariable(t, "DOCKER_API_VERSION", customVersion)()

	opts := &flags.CommonOptions{}
	configFile := &configfile.ConfigFile{}
	apiclient, err := NewAPIClientFromFlags(opts, configFile)
	require.NoError(t, err)
	assert.Equal(t, customVersion, apiclient.ClientVersion())
}

// TODO: move to gotestyourself
func patchEnvVariable(t *testing.T, key, value string) func() {
	oldValue, ok := os.LookupEnv(key)
	require.NoError(t, os.Setenv(key, value))
	return func() {
		if !ok {
			require.NoError(t, os.Unsetenv(key))
			return
		}
		require.NoError(t, os.Setenv(key, oldValue))
	}
}
func TestGetTag(t *testing.T) {
	ref, err := reference.ParseNormalizedNamed("ubuntu@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2")
	assert.NoError(t, err)
	tag := getTag(ref)
	assert.Equal(t, "", tag)

	ref, err = reference.ParseNormalizedNamed("alpine:latest")
	assert.NoError(t, err)
	tag = getTag(ref)
	assert.Equal(t, tag, "latest")

	ref, err = reference.ParseNormalizedNamed("alpine")
	assert.NoError(t, err)
	tag = getTag(ref)
	assert.Equal(t, tag, "")
}

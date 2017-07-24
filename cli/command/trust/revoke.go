package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newRevokeCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [OPTIONS]",
		Short: "Remove trust for an image",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newSignerCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signer [OPTIONS]",
		Short: "Manage trusted signers for an image",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

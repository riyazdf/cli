package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newConfigCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config [OPTIONS]",
		Short: "Configure trust settings",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

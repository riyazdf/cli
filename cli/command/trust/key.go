package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newKeyCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key [OPTIONS]",
		Short: "Operates on signing keys",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

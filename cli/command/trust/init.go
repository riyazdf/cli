package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newInitCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init [OPTIONS]",
		Short: "Initialize trust for an image without pushing",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

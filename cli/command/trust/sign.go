package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newSignCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign [OPTIONS]",
		Short: "Sign an image",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

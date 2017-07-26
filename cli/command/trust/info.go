package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

type infoOptions struct {
	tagsOnly bool
	keysOnly bool
}

func newInfoCommand(dockerCli command.Cli) *cobra.Command {
	var opts infoOptions
	cmd := &cobra.Command{
		Use:   "info [OPTIONS]",
		Short: "Display detailed information about keys and signatures",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	flags := cmd.Flags()
	flags.BoolVarP(&opts.tagsOnly, "tags-only", "t", false, "Show all signed tags only")
	flags.BoolVarP(&opts.keysOnly, "keys-only", "k", false, "Show only keys and delegations known to the repo")
	return cmd
}

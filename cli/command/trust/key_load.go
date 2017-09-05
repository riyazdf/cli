package trust

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary"
	"github.com/docker/notary/storage"
	"github.com/docker/notary/utils"
	"github.com/spf13/cobra"
)

func newKeyLoadCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key-load KEY [KEY...] ",
		Short: "Load a signing key",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return loadKeys(dockerCli, args)
		},
	}
	return cmd
}

func loadKeys(cli command.Streams, keyPaths []string) error {
	trustDir := trust.GetTrustDirectory()
	keyFileStore, err := storage.NewPrivateKeyFileStorage(filepath.Join(trustDir, notary.PrivDir), notary.KeyExtension)
	if err != nil {
		return err
	}
	privKeyImporters := []utils.Importer{keyFileStore}

	var lastImportErr error
	for _, keyPath := range keyPaths {
		from, err := os.OpenFile(keyPath, os.O_RDONLY, notary.PrivExecPerms)
		if err != nil {
			return err
		}
		defer from.Close()
		// Always use a fresh passphrase retriever for each import
		if err = utils.ImportKeys(from, privKeyImporters, "", "", trust.GetBlankPassphraseRetriever(cli)); err != nil {
			fmt.Fprintf(cli.Out(), "error importing key from %s: %s\n", keyPath, err)
			lastImportErr = err
		} else {
			fmt.Fprintf(cli.Out(), "successfully imported key from %s\n", keyPath)
		}
	}
	return lastImportErr
}

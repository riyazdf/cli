package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary"
	"github.com/docker/notary/storage"
	"github.com/docker/notary/utils"
	"github.com/spf13/cobra"
)

const (
	ownerReadOnlyPerms     = 0400
	ownerReadAndWritePerms = 0600
)

func newKeyLoadCommand(dockerCli command.Streams) *cobra.Command {
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

func loadKeys(streams command.Streams, keyPaths []string) error {
	trustDir := trust.GetTrustDirectory()
	keyFileStore, err := storage.NewPrivateKeyFileStorage(filepath.Join(trustDir, notary.PrivDir), notary.KeyExtension)
	if err != nil {
		return err
	}
	privKeyImporters := []utils.Importer{keyFileStore}

	var errKeyPaths []string
	for _, keyPath := range keyPaths {
		fmt.Fprintf(streams.Out(), "\nLoading key from \"%s\"...\n", keyPath)

		// Always use a fresh passphrase retriever for each import
		passRet := trust.GetPassphraseRetriever(streams.In(), streams.Out())
		if err := loadKeyFromPath(privKeyImporters, keyPath, passRet); err != nil {
			fmt.Fprintf(streams.Out(), "error importing key from %s: %s\n", keyPath, err)
			errKeyPaths = append(errKeyPaths, keyPath)
		} else {
			fmt.Fprintf(streams.Out(), "Successfully imported key from %s\n", keyPath)
		}
	}
	if len(errKeyPaths) > 0 {
		return fmt.Errorf("Error importing keys from: %s", strings.Join(errKeyPaths, ", "))
	}
	return nil
}

func loadKeyFromPath(privKeyImporters []utils.Importer, keyPath string, passRet notary.PassRetriever) error {
	fileInfo, err := os.Stat(keyPath)
	if err != nil {
		return err
	}
	if fileInfo.Mode() != ownerReadOnlyPerms && fileInfo.Mode() != ownerReadAndWritePerms {
		return fmt.Errorf("private key permission from %s should be set to 400 or 600", keyPath)
	}
	from, err := os.OpenFile(keyPath, os.O_RDONLY, notary.PrivExecPerms)
	if err != nil {
		return err
	}
	defer from.Close()
	return utils.ImportKeys(from, privKeyImporters, "signer", "", passRet)
}

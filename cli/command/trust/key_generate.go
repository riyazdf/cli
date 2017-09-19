package trust

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/notary"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	tufutils "github.com/docker/notary/tuf/utils"
	"github.com/spf13/cobra"
)

func newKeyGenerateCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key-generate NAME [NAME...]",
		Short: "Generate a signing key",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateKeys(dockerCli, args)
		},
	}
	return cmd
}

func generateKeys(streams command.Streams, keyNames []string) error {
	var genKeyErrs []string
	for _, keyName := range keyNames {
		if err := generateKey(streams, keyName); err != nil {
			fmt.Fprintf(streams.Out(), err.Error())
			genKeyErrs = append(genKeyErrs, keyName)
		}
	}

	if len(genKeyErrs) > 0 {
		return fmt.Errorf("Error generating keys for: %s", strings.Join(genKeyErrs, ", "))
	}
	return nil
}

func generateKey(streams command.Streams, keyName string) error {
	fmt.Fprintf(streams.Out(), "\nGenerating key for %s...\n", keyName)
	privKey, err := tufutils.GenerateKey(data.ECDSAKey)
	if err != nil {
		return err
	}

	// Automatically load the private key to local storage for use
	privKeyFileStore, err := trustmanager.NewKeyFileStore(trust.GetTrustDirectory(), trust.GetPassphraseRetriever(streams.In(), streams.Out()))
	if err != nil {
		return err
	}

	privKeyFileStore.AddKey(trustmanager.KeyInfo{Role: data.RoleName(keyName)}, privKey)
	if err != nil {
		return err
	}

	pubKey := data.PublicKeyFromPrivate(privKey)
	pubPEM := pem.Block{
		Type: "PUBLIC KEY",
		Headers: map[string]string{
			"role": keyName,
		},
		Bytes: pubKey.Public(),
	}

	// Output the public key to a file in the CWD
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	pubFileName := strings.Join([]string{keyName, "pub"}, ".")
	pubFilePath := filepath.Join(cwd, pubFileName)
	if err := ioutil.WriteFile(pubFilePath, pem.EncodeToMemory(&pubPEM), notary.PrivNoExecPerms); err != nil {
		return err
	}
	fmt.Fprintf(streams.Out(), "Successfully generated and loaded private key. Corresponding public key available: %s\n", pubFileName)
	return nil
}

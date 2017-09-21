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
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, keyName := range keyNames {
		fmt.Fprintf(streams.Out(), "\nGenerating key for %s...\n", keyName)
		freshPassRet := trust.GetPassphraseRetriever(streams.In(), streams.Out())
		if err := generateKey(keyName, cwd, trust.GetTrustDirectory(), freshPassRet); err != nil {
			fmt.Fprintf(streams.Out(), err.Error())
			genKeyErrs = append(genKeyErrs, keyName)
		} else {
			pubFileName := strings.Join([]string{keyName, "pub"}, ".")
			fmt.Fprintf(streams.Out(), "Successfully generated and loaded private key. Corresponding public key available: %s\n", pubFileName)
		}
	}

	if len(genKeyErrs) > 0 {
		return fmt.Errorf("Error generating keys for: %s", strings.Join(genKeyErrs, ", "))
	}
	return nil
}

func generateKey(keyName, pubDir, privTrustDir string, passRet notary.PassRetriever) error {
	privKey, err := tufutils.GenerateKey(data.ECDSAKey)
	if err != nil {
		return err
	}

	// Automatically load the private key to local storage for use
	privKeyFileStore, err := trustmanager.NewKeyFileStore(privTrustDir, passRet)
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
	pubFileName := strings.Join([]string{keyName, "pub"}, ".")
	pubFilePath := filepath.Join(pubDir, pubFileName)
	if err := ioutil.WriteFile(pubFilePath, pem.EncodeToMemory(&pubPEM), notary.PrivNoExecPerms); err != nil {
		return err
	}
	return nil
}

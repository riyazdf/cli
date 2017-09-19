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
	"github.com/pkg/errors"
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
	var (
		chosenPassphrase string
		giveup           bool
		pemPrivKey       []byte
	)
	keyID := privKey.ID()
	passRet := trust.GetPassphraseRetriever(streams.In(), streams.Out())
	fmt.Fprintf(streams.Out(), "Encrypting private key material for %s...\n", keyName)
	for attempts := 0; ; attempts++ {
		chosenPassphrase, giveup, err = passRet(keyID, "", true, attempts)
		if err == nil {
			break
		}
		if giveup || attempts > 10 {
			return trustmanager.ErrAttemptsExceeded{}
		}
	}

	if chosenPassphrase != "" {
		pemPrivKey, err = tufutils.ConvertPrivateKeyToPKCS8(privKey, data.RoleName(keyName), "", chosenPassphrase)
		if err != nil {
			return err
		}
	} else {
		return errors.New("no password provided")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	privFileName := strings.Join([]string{strings.Join([]string{keyName, "key"}, "-"), "priv"}, ".")
	privFilePath := filepath.Join(cwd, privFileName)
	pubFileName := strings.Join([]string{keyName, "pub"}, ".")
	pubFilePath := filepath.Join(cwd, pubFileName)

	err = ioutil.WriteFile(privFilePath, pemPrivKey, notary.PrivNoExecPerms)
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
	if err := ioutil.WriteFile(pubFilePath, pem.EncodeToMemory(&pubPEM), notary.PrivNoExecPerms); err != nil {
		return err
	}
	fmt.Fprintf(streams.Out(), "Successfully generated encrypted private key %s and public key %s\n", privFileName, pubFileName)
	return nil
}

package cmd

import (
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/rot256/gruppe/ring"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Generate ring signatures on messages",
	Long:  `/`,
	Run: func(cmd *cobra.Command, args []string) {
		msg, err := cmd.Flags().GetString(optMsg)
		if err != nil {
			panic(err)
		}

		sigPath, err := cmd.Flags().GetString(optSig)

		allowEmpty, err := cmd.Flags().GetBool(optAllowEmpty)

		pks := loadPublicKeys(cmd, allowEmpty)

		// load the (encrypted) secret keys on the local machine
		pairs, err := LoadLocalEncKeyPairs()
		if err != nil {
			panic(err)
		}

		// find matches between ring members and local keys
		matches, err := FindMatches(pks, pairs)

		verbose(cmd, "SSH lkeys in ring (+ indicates available for signing):")
		for i, key := range pks {
			match := false
			for _, m := range matches {
				if m.PK.Equals(key) {
					match = true
				}
			}
			if match {
				verbose(cmd, fmt.Sprintf(" + [ %03d ] : %s", i, key.Name()))
			} else {
				verbose(cmd, fmt.Sprintf("   [ %03d ] : %s", i, key.Name()))
			}
		}

		// attempt to use unecrypted secret key
		var selected *ring.KeyPair
		for _, pair := range matches {
			sk, err := ssh.ParseRawPrivateKey([]byte(pair.SKPEM))
			if err == nil {
				selected = &ring.KeyPair{
					PK: pair.PK,
					SK: sk,
				}
				break
			}
		}

		// if not unencrypted pair was found, ask user to decrypt
		if selected != nil {
			fmt.Println("Using :", selected.PK.Name())
		} else {
			// TODO select and decrypt
			panic(nil)
		}

		// generate ring signature
		sig := ring.Sign(*selected, pks, []byte(msg))

		data, err := asn1.Marshal(sig)
		if err != nil {
			panic(err)
		}

		sigFile, err := os.Create(sigPath)
		if err != nil {
			exitError("Failed to create signature file:", err)
		}

		if _, err := sigFile.Write(data); err != nil {
			exitError("Failed to write signature to disk:", err)
		}
	},
}

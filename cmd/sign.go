package cmd

import (
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/rot256/git-ring/ring"
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
		if err != nil {
			panic(err)
		}

		// open the file (better to fail before touching the network)
		sigFile, err := os.Create(sigPath)
		if err != nil {
			exitError("Failed to create signature file:", err)
		}

		// load public keys from different sources
		sourcesTotal, sourcesWithKeys, pks := loadPublicKeys(cmd)

		// check if all entities covered
		allowEmpty, err := cmd.Flags().GetBool(optAllowEmpty)

		if err != nil {
			panic(err)
		}

		if sourcesTotal != sourcesWithKeys && !allowEmpty {
			printError("Error: Obtained zero keys from one/more sources:")
			printError("THEY (SHOWN IN YELLOW) WILL NOT BE INCLUDED IN THE RING.")
			printError("Aborting to avoid accidentially excluding an entity from the ring.")
			printError("If you want to allow this use --" + optAllowEmpty)
			exitError()
		}

		// load the (encrypted) secret keys on the local machine
		pairs, err := loadLocalEncKeyPairs()
		if err != nil {
			panic(err)
		}

		// find matches between ring members and local keys
		matches := findMatches(pks, pairs)
		if len(matches) == 0 {
			exitError("Error: No matching keys found:\nDid you remember to include yourself in the ring?")
		}

		verbose(cmd, "SSH keys in ring (available keys marked with +):\n")
		for i, key := range pks {
			match := false
			for _, m := range matches {
				if m.PK.Equals(key) {
					match = true
				}
			}
			if match {
				verbose(cmd, colorBlue)
				verbose(cmd, fmt.Sprintf(" + [ %03d ] : %s\n", i, key.Name()))
				verbose(cmd, colorReset)
			} else {
				verbose(cmd, fmt.Sprintf("   [ %03d ] : %s\n", i, key.Name()))
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
		if selected == nil {
			// TODO select and decrypt
			exitError("Decrypt key")
		}

		// generate ring signature
		sig := ring.Sign(*selected, pks, []byte(msg))

		// serialize signature to file
		data, err := asn1.Marshal(sig)
		if err != nil {
			panic(err)
		}
		if _, err := sigFile.Write(data); err != nil {
			exitError("Failed to write signature to disk:", err)
		}

		fmt.Print(colorBlue)
		fmt.Println("Signature successfully generated")
		fmt.Printf("Saved in: %s (%d bytes)\n", sigPath, len(data))
		fmt.Print(colorReset)
	},
}

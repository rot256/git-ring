package cmd

import (
	"encoding/asn1"
	"fmt"
	"io"
	"os"

	"github.com/rot256/git-ring/ring"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify ring signatures",
	Long:  `/`,
	Run: func(cmd *cobra.Command, args []string) {

		sigPath, err := cmd.Flags().GetString(optSig)
		if err != nil {
			panic(err)
		}

		sigFile, err := os.Open(sigPath)
		if err != nil {
			exitError("Failed to open signature file:", err)
		}

		sigData, err := io.ReadAll(sigFile)
		if err != nil {
			exitError("Failed to read signature file:", err)
		}

		var sig ring.Signature
		rest, err := asn1.Unmarshal(sigData, &sig)
		if err != nil {
			exitError("Failed to deserialize signature:", err)
		}
		if len(rest) != 0 {
			exitError("Signature is followed by junk")
		}

		_, _, pks := loadPublicKeys(cmd)

		msg, err := sig.Verify(pks)
		if err != nil {
			printError("Signature is not valid:")
			exitError(err)
		}

		fmt.Println("Message:")
		fmt.Println(string(msg))
	},
}

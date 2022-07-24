package cmd

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/rot256/gruppe/ring"
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
			printError("Failed to open signature file:", err)
		}

		sigData, err := ioutil.ReadAll(sigFile)
		if err != nil {
			printError("Failed to read signature file:", err)
		}

		var sig ring.Signature
		rest, err := asn1.Unmarshal(sigData, &sig)
		if err != nil {
			printError("Failed to deserialize signature:", err)
		}
		if len(rest) != 0 {
			printError("Signature is followed by junk")
		}

		pks := loadPublicKeys(cmd, true)

		msg, err := sig.Verify(pks)
		if err != nil {
			printError("Signature is not valid:")
		}

		fmt.Println("msg:", msg)

	},
}

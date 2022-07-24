package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgSig string
var cfgMsg string
var cfgGithub string
var cfgGitlab string

const optVerbose = "verbose"
const optMsg = "msg"
const optSig = "sig"
const optGithub = "github"
const optGitlab = "gitlab"
const optSSHKeys = "keys"
const optUrls = "url"
const optAllowEmpty = "allow-empty"

var rootCmd = &cobra.Command{
	Use:   "sjak",
	Short: "Sjak: Easy SSH Ring Signatures",
	Long:  `/`,
	Run:   func(cmd *cobra.Command, args []string) {},
}

func init() {
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)

	// global flags
	rootCmd.PersistentFlags().BoolP(optVerbose, "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringArray(optUrls, []string{}, "URLs with lists of keys to include")
	rootCmd.PersistentFlags().StringArray(optSSHKeys, []string{}, "Paths to SSH keys to include in the ring")
	rootCmd.PersistentFlags().StringArray(optGitlab, []string{}, "Gitlab usernames/organizations to include in the ring")
	rootCmd.PersistentFlags().StringArray(optGithub, []string{}, "Github usernames/organizations to include in the ring")

	// flags specific to signing
	signCmd.PersistentFlags().StringP(optSig, "s", "", "Path to signature to create (file cannot exist)")
	signCmd.PersistentFlags().StringP(optMsg, "m", "", "Message to sign")
	signCmd.PersistentFlags().Bool(optAllowEmpty, false, "Allow retrieving zero keys from a source")
	signCmd.MarkPersistentFlagRequired(optMsg)
	signCmd.MarkPersistentFlagRequired(optSig)

	// flags specific to verification
	verifyCmd.PersistentFlags().StringP(optSig, "s", "", "Path to signature to verify")
	verifyCmd.MarkPersistentFlagRequired(optSig)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

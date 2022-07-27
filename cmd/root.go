package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "git-ring"
const appUrl = "https://github.com/rot256/git-ring"

const optVerbose = "verbose"
const optMsg = "msg"
const optSig = "sig"
const optGithub = "github"
const optGitlab = "gitlab"
const optSSHKeys = "ssh-key"
const optUrls = "url"
const optAllowEmpty = "allow-empty"

func description() string {
	s := ""
	s += "Heterogeneous ring signatures for SSH keys.\n"
	s += "An easy and private way to prove membership among a set of git users.\n"
	s += "More info: " + appUrl
	return s
}

var rootCmd = &cobra.Command{
	Use:   appName,
	Short: appName + ": Easy SSH Ring Signatures",
	Long:  description(),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)

	// global flags
	rootCmd.PersistentFlags().StringP(optSig, "s", "ring.sig", "Path to signature")
	rootCmd.PersistentFlags().BoolP(optVerbose, "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringArray(optUrls, []string{}, "URLs with lists of keys to include")
	rootCmd.PersistentFlags().StringArray(optSSHKeys, []string{}, "Paths to SSH keys to include in the ring")
	rootCmd.PersistentFlags().StringArray(optGitlab, []string{}, "Gitlab usernames/organizations to include in the ring")
	rootCmd.PersistentFlags().StringArray(optGithub, []string{}, "Github usernames/organizations to include in the ring")

	// flags specific to signing
	signCmd.PersistentFlags().StringP(optMsg, "m", "", "Message to sign")
	signCmd.PersistentFlags().Bool(optAllowEmpty, false, "Allow retrieving zero keys from a source")
	signCmd.MarkPersistentFlagRequired(optMsg)
	signCmd.MarkPersistentFlagRequired(optSig)

	// flags specific to verification
	verifyCmd.MarkPersistentFlagRequired(optSig)
}

func Execute() { //nolint:golint
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

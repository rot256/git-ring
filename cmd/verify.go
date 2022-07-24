package cmd

import "github.com/spf13/cobra"

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify ring signatures",
	Long:  `/`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

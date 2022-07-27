package cmd

import (
	"fmt"

	"github.com/rot256/git-ring/ring"
)

func loadGitlabUser(indent string, name string) []ring.PublicKey {
	url := "https://gitlab.com/" + name + ".keys"
	keys, err := fetchKeys(url)
	if err != nil {
		exitError("Failed to fetch keys for Gitlab user", name, "err:", err)
	}

	colorWarnBool(len(keys) > 0)
	fmt.Println(" ", len(keys), "keys :", name)
	fmt.Print(colorReset)

	return keys
}

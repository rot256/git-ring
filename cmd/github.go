package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rot256/git-ring/ring"
)

type githubOrgMember struct {
	Login string
	Type  string
}

// TODO: allow supplying credentials to fetch private orgs
func githubOrganizationUsers(name string) (bool, []string, error) {
	membersPerPage := 100

	var names []string

	for n := 1; ; n += 1 {
		url := fmt.Sprintf("https://api.github.com/orgs/%s/members?page=%d&per_page=%d", name, n, membersPerPage)
		resp, err := http.Get(url)

		if err != nil {
			return false, []string{}, err
		}

		// stop if org not found
		if resp.StatusCode == http.StatusNotFound {
			return false, []string{}, nil
		}

		// check for error
		if resp.StatusCode != http.StatusOK {
			return false, []string{}, fmt.Errorf("HTTP request failed with: %s", resp.Status)
		}

		// read response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, []string{}, err
		}

		// deserialize json
		var members []githubOrgMember
		if err != nil {
			return false, []string{}, err
		}
		json.Unmarshal(body, &members)

		// add to user names
		for _, m := range members {
			if m.Type == "User" {
				names = append(names, m.Login)
			}
		}

		if len(members) < membersPerPage {
			break
		}
	}

	return true, names, nil
}

func loadGithubUser(indent string, name string) []ring.PublicKey {
	url := "https://github.com/" + name + ".keys"
	keys, err := fetchKeys(url)
	if err != nil {
		exitError("Failed to fetch keys for Github user", name, "err:", err)
	}

	colorWarnBool(len(keys) > 0)
	fmt.Printf("%s%s (%d keys)\n", indent, name, len(keys))
	fmt.Print(colorReset)

	return keys
}

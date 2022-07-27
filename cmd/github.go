package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/rot256/git-ring/ring"
)

const githubEnvUsername = "GITHUB_USERNAME"
const githubEnvToken = "GITHUB_TOKEN"

type githubOrgMember struct {
	Login string
	Type  string
}

// TODO: allow supplying credentials to fetch private orgs
func githubOrganizationUsers(name string) (bool, []string, error) {

	username, ok := os.LookupEnv(githubEnvUsername)
	basicAuth := ok

	password, ok := os.LookupEnv(githubEnvToken)
	basicAuth = basicAuth && ok

	membersPerPage := 100

	var names []string
	var client http.Client

	for n := 1; ; n += 1 {
		req, err := http.NewRequest(
			http.MethodGet,
			fmt.Sprintf("https://api.github.com/orgs/%s/members?page=%d&per_page=%d", name, n, membersPerPage),
			bytes.NewReader([]byte{}), // empty body
		)
		if err != nil {
			panic(err)
		}

		// use basic auth (if supplied)
		if basicAuth {
			req.SetBasicAuth(username, password)
		}

		//
		resp, err := client.Do(req)
		if err != nil {
			return false, nil, err
		}

		// stop if org not found
		if resp.StatusCode == http.StatusNotFound {
			return false, nil, nil
		}

		// check for error
		if resp.StatusCode != http.StatusOK {
			return false, nil, fmt.Errorf("HTTP request failed with: %s", resp.Status)
		}

		// read response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, nil, err
		}

		// deserialize json
		var members []githubOrgMember
		if err := json.Unmarshal(body, &members); err != nil {
			return false, nil, err
		}

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

package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rot256/gruppe/ring"
	"github.com/spf13/cobra"
)

type githubOrgMember struct {
	Login string
}

// TODO: allow supplying credentials to fetch private orgs
func githubOrganizationUsers(name string) (bool, []string, error) {
	membersPerPage := 100

	var names []string

	for n := 1; ; n += 1 {
		url := fmt.Sprintf("https://api.github.com/orgs/%s/members?page=%d&per_page=%d", name, n, membersPerPage)
		resp, err := http.Get(url)

		// stop if org not found
		if resp.StatusCode == http.StatusNotFound {
			return false, []string{}, nil
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
			names = append(names, m.Login)
		}

		if len(members) < membersPerPage {
			break
		}
	}

	return true, names, nil
}

func verbose(cmd *cobra.Command, s ...interface{}) {
	if enabled, _ := cmd.Flags().GetBool(optVerbose); enabled {
		fmt.Println(s...)
	}
}

func printError(s ...interface{}) {
	fmt.Println(s...)
}

func exitError(s ...interface{}) {
	if len(s) > 0 {
		printError(s...)
	}
	os.Exit(1)
}

func loadGithubUser(indent string, name string) []ring.PublicKey {
	url := "https://github.com/" + name + ".keys"
	keys, err := fetchKeys(url)
	if err != nil {
		exitError("Failed to fetch keys for Github user", name, "err:", err)
	}
	fmt.Println(indent, len(keys), "keys :", name, "@ Github")
	return keys
}

func loadPublicKeys(cmd *cobra.Command, allowEmpty bool) []ring.PublicKey {
	var pks []ring.PublicKey

	zeroKeys := false

	//

	fmt.Println("Loading keys in ring:")

	// load github keys
	githubNames, _ := cmd.Flags().GetStringArray(optGithub)
	for _, name := range githubNames {
		isOrg, members, err := githubOrganizationUsers(name)
		if err != nil {
			exitError("Failed check for Github org:", err)
		}

		if isOrg {
			fmt.Println("  Github Org:", name)
			for _, member := range members {
				keys := loadGithubUser("   ", member)
				zeroKeys = zeroKeys || len(keys) == 0
				pks = append(pks, keys...)
			}
		} else {
			keys := loadGithubUser(" ", name)
			fmt.Println(" ", len(keys), "keys :", name, "@ Github")
			zeroKeys = zeroKeys || len(keys) == 0
			pks = append(pks, keys...)
		}
	}

	// load gitlab keys
	gitlabNames, _ := cmd.Flags().GetStringArray(optGitlab)
	for _, name := range gitlabNames {
		url := "https://gitlab.com/" + name + ".keys"
		keys, err := fetchKeys(url)
		if err != nil {
			exitError("Failed to fetch keys for Gitlab user", name, "err:", err)
		}
		fmt.Println(" ", len(keys), "keys :", name, "@ Gitlab")
		zeroKeys = zeroKeys || len(keys) == 0
		pks = append(pks, keys...)
	}

	// fetch keys from other urls
	urls, _ := cmd.Flags().GetStringArray(optUrls)
	for _, url := range urls {
		keys, err := fetchKeys(url)
		if err != nil {
			exitError("Failed to fetch keys for Gitlab user", url, "err:", err)
		}
		fmt.Println(" ", len(keys), "keys :", url)
		zeroKeys = zeroKeys || len(keys) == 0
		pks = append(pks, keys...)
	}

	// read local keys

	if zeroKeys && !allowEmpty {
		printError("Obtained zero keys from one/more sources:")
		printError("  Aborting to avoid excluding a source from the ring")
		printError("  If you want to allow this use --" + optAllowEmpty)
		exitError()
	}

	// sort and deuplicate the keys
	pks = sortAndDedupKeys(pks)
	fmt.Println(len(pks), "total keys in ring")
	return pks
}

// this is used to avoid leaking the order in which the keys were fetched
func sortAndDedupKeys(pks []ring.PublicKey) []ring.PublicKey {
	// deduplicate the keys
	set := make(map[string]ring.PublicKey)
	for _, pk := range pks {
		set[pk.Id()] = pk
	}

	// sort id's
	sorted := make([]string, 0)
	for k, _ := range set {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	// retrieve keys in sorted order
	pksNew := make([]ring.PublicKey, 0, len(set))
	for _, k := range sorted {
		pksNew = append(pksNew, set[k])
	}
	return pksNew
}

func fetchKeys(url string) ([]ring.PublicKey, error) {
	var keys []ring.PublicKey

	resp, err := http.Get(url)
	if err != nil {
		return keys, err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		pk, err := ring.PublicKeyFromStr(scanner.Text())
		if err != nil {
			log.Println("Found invalid public key")
			continue
		}
		keys = append(keys, pk)
	}

	if err := scanner.Err(); err != nil {
		return keys, err
	}

	return keys, nil
}

func FetchAllKeys(urls []string) ([]ring.PublicKey, error) {
	var keys []ring.PublicKey

	for _, url := range urls {
		newKeys, err := fetchKeys(url)
		if err != nil {
			return keys, err
		}
		if len(newKeys) == 0 {
			log.Fatalln("One of the urls specified holds no keys!")
		}
		fmt.Println("Loaded", len(newKeys), "keys from:", url)
		keys = append(keys, newKeys...)
	}

	return sortAndDedupKeys(keys), nil
}

func FindMatches(pks []ring.PublicKey, pairs []ring.EncKeyPair) ([]ring.EncKeyPair, error) {
	// create lookup
	index := make(map[string]bool)
	for _, pk := range pks {
		index[pk.Id()] = true
	}

	// find all pairs which was present in the list of public key
	var matches []ring.EncKeyPair
	for _, pair := range pairs {
		if index[pair.PK.Id()] {
			matches = append(matches, pair)
		}
	}

	return matches, nil
}

func LoadLocalEncKeyPairs() ([]ring.EncKeyPair, error) {
	var pairs []ring.EncKeyPair

	// list files in ./ssh directory
	home, err := os.UserHomeDir()
	if err != nil {
		return pairs, err
	}

	sshDir := filepath.Join(home, "/.ssh")
	key_files, err := ioutil.ReadDir(sshDir)
	if err != nil {
		return pairs, err
	}

	// add all pairs of public/secret keys found in .ssh
	for _, entry := range key_files {
		// ignore directories
		if entry.IsDir() {
			continue
		}

		// ignores public keys
		if strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}

		// read suspected private key
		pathSK := filepath.Join(sshDir, entry.Name())
		skPEM, err := ioutil.ReadFile(pathSK)
		if err != nil {
			continue
		}

		// read corresponding public key
		pathPK := filepath.Join(sshDir, entry.Name()+".pub")
		pk_data, err := ioutil.ReadFile(pathPK)
		if err != nil {
			continue
		}

		// parse public key
		pk, err := ring.PublicKeyFromStr(string(pk_data))
		if err != nil {
			panic(err)
		}

		pairs = append(
			pairs,
			ring.EncKeyPair{
				SKPEM: string(skPEM),
				PK:    pk,
			},
		)
	}

	return pairs, nil
}

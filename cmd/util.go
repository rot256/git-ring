package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rot256/git-ring/ring"
	"github.com/spf13/cobra"
)

func verbose(cmd *cobra.Command, s ...interface{}) {
	if enabled, _ := cmd.Flags().GetBool(optVerbose); enabled {
		fmt.Print(s...)
	}
}

func printError(s ...interface{}) {
	fmt.Print(colorRed)
	fmt.Println(s...)
	fmt.Print(colorReset)
}

func exitError(s ...interface{}) {
	if len(s) > 0 {
		printError(s...)
	}
	os.Exit(1)
}

func loadUrl(indent string, url string) []ring.PublicKey {
	keys, err := fetchKeys(url)
	if err != nil {
		exitError("Failed to fetch keys from url:", url)
	}

	colorWarnBool(len(keys) > 0)
	fmt.Println(" ", len(keys), "keys :", url)
	fmt.Print(colorReset)

	return keys
}

func loadPublicKeys(cmd *cobra.Command) (int, int, []ring.PublicKey) {
	//

	var sourcesTotal int
	var sourcesWithKeys int
	var pks []ring.PublicKey

	fmt.Println("Loading Keys from Different Entities:")

	addKeys := func(keys []ring.PublicKey) {
		if len(keys) > 0 {
			sourcesWithKeys += 1
		}
		sourcesTotal += 1
		pks = append(pks, keys...)
	}

	// load github keys

	githubNames, _ := cmd.Flags().GetStringArray(optGithub)
	if len(githubNames) >= 0 {
		fmt.Print(colorCyan)
		fmt.Println("Github:")
		fmt.Print(colorReset)
	}

	for _, name := range githubNames {
		isOrg, members, err := githubOrganizationUsers(name)
		if err != nil {
			printError("Failed check for Github org:")
			exitError(err)
		}

		if isOrg {
			fmt.Print(colorPurple)
			fmt.Println(indent+"Organization:", name)
			fmt.Print(colorReset)
			for _, member := range members {
				addKeys(loadGithubUser(indent+indent, member))
			}
		} else {
			addKeys(loadGithubUser(indent, name))
		}
	}

	// load gitlab keys
	gitlabNames, _ := cmd.Flags().GetStringArray(optGitlab)
	for _, name := range gitlabNames {
		addKeys(loadGitlabUser(" ", name))
	}

	// fetch keys from other urls
	urls, _ := cmd.Flags().GetStringArray(optUrls)
	for _, url := range urls {
		addKeys(loadUrl(" ", url))
	}

	// sort and deuplicate the keys
	pks = sortAndDedupKeys(pks)
	fmt.Println(len(pks), "Keys in the ring.")
	fmt.Println("Covering:", sourcesWithKeys, "/", sourcesTotal, "entities")
	return sourcesTotal, sourcesWithKeys, pks
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
	for k := range set {
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

func findMatches(pks []ring.PublicKey, pairs []ring.EncKeyPair) []ring.EncKeyPair {
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

	return matches
}

func loadLocalEncKeyPairs() ([]ring.EncKeyPair, error) {
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

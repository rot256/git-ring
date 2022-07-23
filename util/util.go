package util

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

	"github.com/rot256/gruppe/ring"
)

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

package main

import (
	"bufio"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

type PublicKey struct {
	pk     ssh.PublicKey
	pk_ssh string // this is only used for displaying (the generated signature does not depend on it)
}

func (p *PublicKey) Id() string {
	return p.pk.Type() + "-" + ssh.FingerprintSHA256(p.pk)
}

type EncKeyPair struct {
	pk     PublicKey
	sk_pem string // PEM serialized private key
}

type KeyPair struct {
	pk PublicKey
	sk interface{}
}

func (pk1 PublicKey) Equals(pk2 PublicKey) bool {
	return pk1.Id() == pk2.Id()
}

func (k *PublicKey) FP() string {
	return ssh.FingerprintSHA256(k.pk)
}

func (k *PublicKey) Name() string {
	return k.FP() + " (" + k.pk.Type() + ")"
}

func fetchKeys(url string) ([]PublicKey, error) {
	var keys []PublicKey

	resp, err := http.Get(url)
	if err != nil {
		return keys, err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		pk_ssh := strings.TrimSpace(scanner.Text())
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk_ssh))
		if err != nil {
			log.Println("Found invalid public key")
			continue
		}
		keys = append(keys, PublicKey{
			pk,
			pk_ssh,
		})
	}

	if err := scanner.Err(); err != nil {
		return keys, err
	}

	return keys, nil
}

func fetchAllKeys(urls []string) ([]PublicKey, error) {
	var keys []PublicKey

	for _, url := range urls {
		newKeys, err := fetchKeys(url)
		if err != nil {
			return keys, err
		}
		if len(newKeys) == 0 {
			log.Fatalln("One of the urls specified holds no keys!")
		}
		keys = append(keys, newKeys...)
	}

	return keys, nil
}

func findMatches(pks []PublicKey, pairs []EncKeyPair) ([]EncKeyPair, error) {
	// create lookup
	index := make(map[string]bool)
	for _, pk := range pks {
		index[pk.Id()] = true
	}

	// find all pairs which was present in the list of public key
	var matches []EncKeyPair
	for _, pair := range pairs {
		if index[pair.pk.Id()] {
			matches = append(matches, pair)
		}
	}

	return matches, nil
}

func publicKeyFromStr(s string) (PublicKey, error) {
	pk_ssh := strings.TrimSpace(s)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk_ssh))
	if err != nil {
		return PublicKey{}, err
	}

	return PublicKey{
		pk_ssh: pk_ssh,
		pk:     pk,
	}, nil
}

func loadLocalEncKeyPairs() ([]EncKeyPair, error) {
	var pairs []EncKeyPair

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
		pk, err := publicKeyFromStr(string(pk_data))
		if err != nil {
			panic(err)
		}

		pairs = append(
			pairs,
			EncKeyPair{
				sk_pem: string(skPEM),
				pk:     pk,
			},
		)
	}

	return pairs, nil
}

// this is used to avoid leaking the order in which the keys were fetched
func sortAndDedupKeys(pks []PublicKey) []PublicKey {

	// deduplicate the keys
	set := make(map[string]PublicKey)
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
	pksNew := make([]PublicKey, 0, len(set))
	for _, k := range sorted {
		pksNew = append(pksNew, set[k])
	}
	return pksNew
}

func main() {

	urls := []string{
		"https://github.com/rot256.keys",
		"https://github.com/grittygrease.keys",
		"https://github.com/zx2c4.keys",
	}

	// load the public keys of the ring members
	//
	// NOTE: we retrieve ALL keys for each user:
	// this is to prevent privacy leaks where an old unused
	// key is included as the only entry for that user.
	pks, err := fetchAllKeys(urls)
	if err != nil {
		panic(err)
	}

	// sort and deduplicate fetched keys
	// (to avoid leaking the order of inclusion)
	pks = sortAndDedupKeys(pks)

	// load the (encrypted) secret keys on the local machine
	pairs, err := loadLocalEncKeyPairs()
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys In Ring:")
	for i, key := range pks {
		fmt.Println("[", i, "]", key.Name())
	}

	// find matches between ring members and local keys
	matches, err := findMatches(pks, pairs)
	fmt.Println("Matching Keys Found:")
	for i, pair := range matches {
		fmt.Println("[", i, "] :", pair.pk.Name())
	}

	// attempt to use unecrypted secret key
	var selected *KeyPair
	for _, pair := range matches {
		sk, err := ssh.ParseRawPrivateKey([]byte(pair.sk_pem))
		if err == nil {
			selected = &KeyPair{
				pk: pair.pk,
				sk: sk,
			}
			break
		}
	}

	// if not unencrypted pair was found, ask user to decrypt
	if selected != nil {
		fmt.Println("Using :", selected.pk.Name())
	} else {
		// TODO select and decrypt
		panic(nil)
	}

	// generate ring signature
	sig := ringSign(*selected, pks)

	data, err := asn1.Marshal(sig)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(data))
}

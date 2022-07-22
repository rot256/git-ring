package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type PublicKey struct {
	pk     ssh.PublicKey
	pk_ssh string
}

func (p *PublicKey) Id() string {
	return string(p.pk.Marshal())
}

type EncKeyPair struct {
	pk     PublicKey
	sk_pem string // PEM serialized private key
}

type KeyPair struct {
	pk PublicKey
	sk interface{}
}

func fetchKeys(url string) ([]PublicKey, error) {
	var keys []PublicKey

	resp, err := http.Get(url)
	if err != nil {
		return keys, err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
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
		new_keys, err := fetchKeys(url)
		if err != nil {
			return keys, err
		}
		keys = append(keys, new_keys...)
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

func main() {

	urls := []string{
		"https://github.com/rot256.keys",
	}

	pk_keys, err := fetchAllKeys(urls)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(pk_keys)

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	ssh_dir := filepath.Join(home, "/.ssh")

	fmt.Println(ssh_dir)

	key_files, err := ioutil.ReadDir(ssh_dir)
	if err != nil {
		panic(err)
	}

	var keys []EncKeyPair

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
		path_sk := filepath.Join(ssh_dir, entry.Name())
		sk_pem, err := ioutil.ReadFile(path_sk)
		if err != nil {
			continue
		}

		// read corresponding public key
		path_pk := filepath.Join(ssh_dir, entry.Name()+".pub")
		pk_data, err := ioutil.ReadFile(path_pk)
		if err != nil {
			continue
		}

		pk, err := publicKeyFromStr(string(pk_data))
		if err != nil {
			panic(err)
		}

		keys = append(
			keys,
			EncKeyPair{
				sk_pem: string(sk_pem),
				pk:     pk,
			},
		)
	}

	matches, err := findMatches(pk_keys, keys)
	fmt.Println("Matching keys found:")
	for i, pair := range matches {
		fmt.Println("[", i, "] :", pair.pk.pk_ssh)
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

	//
	if selected != nil {
		fmt.Println("Using :", selected.pk.pk_ssh)
	} else {
		// TODO select and decrypt
		panic(nil)
	}

	// generate ring signature
	ringSign(*selected, pk_keys)

}

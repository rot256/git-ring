package cmd

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"strings"

	"github.com/rot256/gruppe/ring"
	"github.com/rot256/gruppe/util"
	"golang.org/x/crypto/ssh"
)

func Sign() {
	var keyLinks []string

	userGithub := flag.String("github", "", "Github usernames seperated by ,")
	userGitlab := flag.String("gitlab", "", "Gitlab usernames seperated by ,")
	msg := flag.String("msg", "", "Message to sign")

	flag.Parse()

	for _, name := range strings.Split(*userGithub, ",") {
		if len(name) > 0 {
			keyLinks = append(keyLinks, "https://github.com/"+name+".keys")
		}
	}

	for _, name := range strings.Split(*userGitlab, ",") {
		if len(name) > 0 {
			keyLinks = append(keyLinks, "https://gitlab.com/"+name+".keys")
		}
	}

	// load the public keys of the ring members
	//
	// NOTE: we retrieve ALL keys for each user:
	// this is to prevent privacy leaks where an old unused
	// key is included as the only entry for that user.
	pks, err := util.FetchAllKeys(keyLinks)
	if err != nil {
		panic(err)
	}

	// load the (encrypted) secret keys on the local machine
	pairs, err := util.LoadLocalEncKeyPairs()
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys In Ring:")
	for i, key := range pks {
		fmt.Println("[", i, "]", key.Name())
	}

	// find matches between ring members and local keys
	matches, err := util.FindMatches(pks, pairs)
	fmt.Println("Matching Keys Found:")
	for i, pair := range matches {
		fmt.Println("[", i, "] :", pair.PK.Name())
	}

	// attempt to use unecrypted secret key
	var selected *ring.KeyPair
	for _, pair := range matches {
		sk, err := ssh.ParseRawPrivateKey([]byte(pair.SKPEM))
		if err == nil {
			selected = &ring.KeyPair{
				PK: pair.PK,
				SK: sk,
			}
			break
		}
	}

	// if not unencrypted pair was found, ask user to decrypt
	if selected != nil {
		fmt.Println("Using :", selected.PK.Name())
	} else {
		// TODO select and decrypt
		panic(nil)
	}

	// generate ring signature
	sig := ring.Sign(*selected, pks, []byte(*msg))

	data, err := asn1.Marshal(sig)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(data))

	fmt.Println(sig.Verify(pks))
	fmt.Println(msg)
}

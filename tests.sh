#!/bin/bash

set -e

MSG="test msg"
SSH_DIRECTORY=/tmp/ring-ssh

rm -rf $SSH_DIRECTORY

mkdir $SSH_DIRECTORY

echo "$SSH_DIRECTORY/id_ecdsa" | ssh-keygen -t ecdsa
echo "$SSH_DIRECTORY/id_ed25519" | ssh-keygen -t ed25519
echo "$SSH_DIRECTORY/id_rsa" | ssh-keygen -b 3072 -t rsa

export SSH_DIRECTORY=$SSH_DIRECTORY

## ECDSA Test ##

# generate signature
./git-ring sign --msg "$MSG" --url https://github.com/torvalds.keys --github rot256 --ssh-key $SSH_DIRECTORY/id_ecdsa.pub

# check against same ring
./git-ring verify --url https://github.com/torvalds.keys --github rot256 --ssh-key $SSH_DIRECTORY/id_ecdsa.pub | grep "$MSG"

# check against superset
./git-ring verify --github torvalds --github gregkh --github rot256 --ssh-key $SSH_DIRECTORY/id_ecdsa.pub | grep "$MSG"

## Ed25519 Test ##

# generate signature
./git-ring sign --msg "$MSG" --gitlab dzaporozhets --ssh-key $SSH_DIRECTORY/id_ed25519.pub

# check against same ring
./git-ring verify --gitlab dzaporozhets --ssh-key $SSH_DIRECTORY/id_ed25519.pub | grep "$MSG"

# check against superset
./git-ring verify --github torvalds --github gregkh --github rot256 --gitlab dzaporozhets --ssh-key $SSH_DIRECTORY/id_ed25519.pub | grep "$MSG"

## RSA Test ##

# generate signature (large ring)
./git-ring sign --msg "$MSG" --allow-empty --github Cloudflare --ssh-key $SSH_DIRECTORY/id_rsa.pub

# check against superset (large ring)
./git-ring verify --github Cloudflare --ssh-key $SSH_DIRECTORY/id_rsa.pub --ssh-key $SSH_DIRECTORY/id_ed25519.pub | grep "$MSG"

<img src="http://rot256.dev/git-ring-icon.svg" align="right" height="300" width="300"/>

# Git-Ring; Easy SSH Ring Signatures

Cryptographically proving that you belong to a group of git users has never been easier.

**Disclaimer:** I take no responsibility the correctness/security/completeness of this software,
this software has not undergone a security audit.
I also do not guarantee that the CLI remains stable, or that the signature format remains backwards compatible.

## Why?

Whistleblowing

One of the few places where we actually have a global repository of keys and associated identities.

## Features

- Support for hetrogenous sets of keys: <br>
  The ring of signers can contain combinations of RSA, Ed25519 and ECDSA keys.
- Perfectly deniability: <br> Signatures are deniable even if people get access to your private keys and/or break the underlaying crypto in the future.
- Easily prove membership among Github/Gitlab users (by just supplying the usernames).
- Easily prove membership of a Github Organization (extension of above).
- Manually include SSH keys in the ring.
- Easy to use (see below).
- Cross platform.

## Example Usage

Git-ring aims to be dead-easy to use and hard to misuse. e.g. running:

```
$ ./git-ring sign --msg "testing git-ring" --github WireGuard
Loading Keys from Different Entities:
Github:
    Organization: WireGuard
        mdlayher (1 keys)
        msfjarvis (2 keys)
        nathanchance (1 keys)
        rot256 (3 keys)
        smaeul (1 keys)
        zx2c4 (1 keys)
9 Keys in the ring.
Covering: 6 / 6 entities
Signature successfully generated
Saved in: ring.sig (1874 bytes)
```

Produces a signature on the message "test" proving that the signer ("rot256" in this case) belongs to the [WireGuard organization on Github](https://github.com/orgs/WireGuard/people).

The signature can then be verified as follows (the path to the signature is "./ring.sig" by default):

```
$ ./git-ring verify --github WireGuard
Loading Keys from Different Entities:
Github:
    Organization: WireGuard
        mdlayher (1 keys)
        msfjarvis (2 keys)
        nathanchance (1 keys)
        rot256 (3 keys)
        smaeul (1 keys)
        zx2c4 (1 keys)
9 Keys in the ring.
Covering: 6 / 6 entities
Message:
testing git-ring
```

Note git-ring signatures include the message being signed to simplify usage.

You can also include individual people in the ring, e.g. using:

```
$ ./git-ring sign --github rot256 --github torvalds --github gregkh --msg "testing git-ring"
```

Proves that one of the following people signed the message "testing git-ring":

- Mathias Hall-Andersen (rot256).
- Linus Torvalds (torvalds).
- Greg Kroah-Hartman (gregkh).


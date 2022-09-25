<img src="https://rot256.dev/git-ring-icon.svg#new" align="right" width="15%"/>

# Git-Ring; Easy SSH Ring Signatures

Anonymously proving that you belong to a set of Github users is now easy.

Git(hub/lab) is one of the few places with a large repository of identities tied to associated public keys, namely,
the list of authorized SSH keys for each user which these platforms make public (e.g. [github.com/rot256.keys](https://github.com/rot256.keys)).
Git-ring exploits this feature to allow anonymously proving membership among a set of users/organizations/repositories on these platforms using ring signatures (a cryptographic tool) -- without revealing your identity.

**Disclaimer:** Although I aim for this software to be usable and not just a demo,
I take no responsibility for the correctness/security/completeness of this software:
the software has not undergone a security audit and should currently be considered in an alpha state.
I also do not guarantee that the CLI remains stable, or that the signature format remains backwards compatible.

There is a [companion post](rot256.dev/post/git-ring) describing how the cryptography in git-ring works.

## Applications

#### Whistleblowing

The primary motivation for ring signatures (e.g. in the seminal work [How to leak a secret](https://people.csail.mit.edu/rivest/pubs/RST01.pdf)
by Rivest, Shamir and Tauman) is that of whistleblowing: suppose you are a member of an organization (e.g. on Github)
and you want to raise an issue either publically or internally.
You could post your revelations anonymously, but how do people know that the claims are not fabrications by someone with no relation to the organization?
You could also raise your concerns with your name attached, so that people can verify that you belong to the organization, but that might have undesired personal ramifications...

Ring signatures (e.g. git-ring) offers a solution to this dilemma: you can prove that you belong to the organization without revealing your identity.

In git-ring, this may look something like this:

```console
$ ./git-ring sign --msg "They are doing bad things, I work there." --github EvilCorp
```

Which creates a signature showing that someone within the organization "EvilCorp" created the message, but does not reveal who.

#### Designed Verifier Signatures

You can also use git-ring to create signatures that can only be verified by a single entity (i.e. not publicly verifiable):
by including the verifying party in the ring, the signature could also be forged by the designed verifier
and hence it is not convincing when passed to a third party. e.g.

```console
$ ./git-ring --msg "Do not pass this on" --github <me> --github <you>
```

Creates a signature on the message "Do not pass this on" under the Github user `<me>` which can only be verified by the user `<you>`.

## Features

- Easy to use (see below).
- Support for hetrogenous sets of keys: <br>
  The ring of signers can contain combinations of RSA, Ed25519 and ECDSA keys <br>
  (i.e. all the types supported by Github).
- Perfectly deniability: <br>
  The real signers identity is hidden even if the adversary get access to private keys or break the cryptography.
- Easily prove membership among Github/Gitlab users.
- Easily prove membership of a Github Organization.
- Supports Github credentials to provide access to hidden organizations / private members.
- Manually include SSH keys in the ring.
- Cross platform.

## Example Usage

Git-ring aims to be dead-easy to use and hard to misuse. e.g. running:

```console
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

```console
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

```console
$ ./git-ring sign --github rot256 --github torvalds --github gregkh --msg "testing git-ring"
```

Proves that one of the following people signed the message "testing git-ring":

- Mathias Hall-Andersen (rot256).
- Linus Torvalds (torvalds).
- Greg Kroah-Hartman (gregkh).

More examples can be found in [the tests for the command-line utility](/tests.sh).

## Installation

If you have a Go enviroment set up, then simply run:

```console
$ go install github.com/rot256/git-ring@latest
```

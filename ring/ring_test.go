package ring

import (
	"math/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

type testKeyPair struct {
	pk string
	sk string
}

var testKeys []testKeyPair = []testKeyPair{
	testKeyPair{
		pk: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC1Gbv1qD9Lj7kX0SgEnN7OEHphcn0xdziUE76MEGLhs6UbWiGvI6akuFw7kWYu1QAtK/pfoRSoxxNKjJURQDOPkO9HBsbk3qutFrvwJsZBAeif/ywyg357+NT2iv0v/bCOL/n/apKTbojdAFsWCrFGienbaTC4iQpAAK9uvj36WE7kFNEJ41y5VlWWm+u7geurJC3lhxyukHsH0g+aidTaFHyVMIPMJG6yK82F4myYAnaCT0I543RzRIldiiaJzJ1Wv1WHiByRhwLs7esggwvZlu1I9jxjFHSWRxDyfg/8SJk1JE/cuDiBltdWhA0YOrRJIyQsp1JdBl1frGgqUql+1mmOzhqOXcYb+OflxAjB4y2FSMwnBZP+AAzRSkbxWvHXbJKZBvrah3CEb3FL8Pri/Jt+dNXKwdOuRriwHKApelaAGZYtQI3++IPyi3lh7+tSi5QUAVCWUycxmSUo0kl09L/oXxkkA+aLQfWGQva6sl+Yg72q5qTApilIDh0uJtjzTd49FsUoiNn3FqRbiXnRYiKJf4HKyLNRWoyptLwttVu0P5cTyBXsCj0ocRcBscWO/P2x/4pnqK3Vn795Fo3OjKjaswmPJu0wrbIn9agQWW6p++RExAqfH7IwReEXb4FGuN4tJPW4vO4ny+uFBGOjS396EK7uJoQ92iKesNJ0qQ==",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdDfXDTEmWgEuj/dTs8nSV+Ec2bczZhJNlRDe+3A2SWoGLlxHjSrq/TQULFrll2JrzSrGiCpQ9/E81G9KoHMErUZKS5aYAPkc/XQrJ/WdN3f5JNM7TfDcO2oYce3IiC+4qm9DuYlRr51TjqUDyoxp5XBXMMyZcGbQguDr9enCRXm9t/3KdTdgmc5PjqQO+OKFV9vkO5xD1hD+snXkIMmaIjTbkUR03CjxHPwJQMtMXWhmuHbSkKXlyeTQLdEfN82F09JYSOhcPxxs5bRbPOurYepgmFPRq3dqwhVu2Cc8lrYXAA4yE1ce66VvfRLyLqpuu0z6WTTA4PwcpYfY5prrroLwzFtYHLzzY/J8+frsbuejym4un96u5Ub4Jh4eqO59BsOm0nFf95wG7HLps7XKxCgUqErXDS7aHOZ9LCmtGno/sB/9bnKIDT5MJWcJO30ohBSNTvxtWgfe6srgohsUOnaQJtFmB346G/YpwJMKgRlL3ri4Ln0z7Yujzj6HO9rM=",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
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
jbQ42WdwmGki0AAAALcm90MjU2QGhleGE=
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMGjtL/v4fT7tGHtNgyw8PphfeqDspm2T4GcnxWt1PVN+VcVtLLl9gULtE+w1t0VWPtTn4hjh9aHk5HySXD2nGfe9og5XXR9qFxwqlJVZTCRTC+tYKdMfm9TqmRn+iFLZIXUlP3gl4b2Cn77bND0UZmWDfldlT+oaGjXyzbjetCBR5O7HKDvN71NbFm1fjzOHlxK55caEZKUdEsge/ndWEl9qfu7gWX9kJwp8PCUPd5Ni8y8wMarA/eUV6Ssw6IhnhNqhFgNY5uKwEDkIAyvL1RssodIq4GLa11L4yvGxzOBiO9NZtaQmRlFvyVECiAYrLE1XN5rM41eg5GrykRnzp",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAzBo7S/7+H0+7Rh7TYMsPD6YX3qg7KZtk+BnJ8VrdT1TflXFbSy5f
YFC7RPsNbdFVj7U5+IY4fWh5OR8klw9pxn3vaIOV10fahccKpSVWUwkUwvrWCnTH5vU6pk
Z/ohS2SF1JT94JeG9gp++2zQ9FGZlg35XZU/qGho18s243rQgUeTuxyg7ze9TWxZtX48zh
5cSueXGhGSlHRLIHv53VhJfan7u4Fl/ZCcKfDwlD3eTYvMvMDGqwP3lFekrMOiIZ4TaoRY
DWObisBA5CAMry9UbLKHSKuBi2tdS+MrxsczgYjvTWbWkJkZRb8lRAogGKyxNVzeazONXo
ORq8pEZ86QAAA8h52fjXedn41wAAAAdzc2gtcnNhAAABAQDMGjtL/v4fT7tGHtNgyw8Pph
feqDspm2T4GcnxWt1PVN+VcVtLLl9gULtE+w1t0VWPtTn4hjh9aHk5HySXD2nGfe9og5XX
R9qFxwqlJVZTCRTC+tYKdMfm9TqmRn+iFLZIXUlP3gl4b2Cn77bND0UZmWDfldlT+oaGjX
yzbjetCBR5O7HKDvN71NbFm1fjzOHlxK55caEZKUdEsge/ndWEl9qfu7gWX9kJwp8PCUPd
5Ni8y8wMarA/eUV6Ssw6IhnhNqhFgNY5uKwEDkIAyvL1RssodIq4GLa11L4yvGxzOBiO9N
ZtaQmRlFvyVECiAYrLE1XN5rM41eg5GrykRnzpAAAAAwEAAQAAAQAHykmF8faLmzy2kAcj
4Y7n20BRJo0piPhD3aIe/5zvrKQ4XUJYM9h+lzOVTgVvcgcTbDNJUyrVTeHwm58cfUFdiu
F9f6Y+DbdKFgndOfgEmoBhHSIDIKgfnoUNoyZhzpYS3C1SlSg54VBoYIZ9ka4NbH9YJq1L
9AWN8wO1393+ppKQuQHF0TAQT6HKEePS2LSjrAQIis8lq2vdvREfbcxWjKhy0aDbU3ztLM
QLIVFsIUGzZFGosyQlu0jOpTJKV2Hl4px0DnV1moy1bxG8kzO+9LP4lgIO7UC/rdbrk7AE
0H7t+ZveEDTxDpuuwTPR8mE9ka4wNHm0qXMEOPMiCPuNAAAAgQDR36rFbXaMuLkbprWBZZ
kD8V4AcF5uKz1WvMpH0BD0DRGo1FwGOMgXpW7QpStvlDIwhHNrKIw2AR+N+xQjzdVfEfWM
2zQu5ZCDq4Ez0NWTkTUTA1m4hklsCU9SJzsMUJPhiqTuyHs1AGhZrIe/i0s19S/kVrG4Xy
RVa5R+WzS9rQAAAIEA85mIJZvb6kZkEBoZlVN5dU825zwsZX6Ah8APyprkh8Fu7WlPqLWu
RgsKUtx8pqHXuijcbF6QpL9+8KvOdZyZ4rdgkTLJvOc9LWnApWFleUBg0GeOkSEFU6OvvO
Fl7eUcsh+kK8URS/HPxI8TVUYG1ac69TfCme6Crzszs/FpAH0AAACBANZ9/dBxi2C6dOKS
VFbve+BVFxmpTvyzOQeVqdoYCHJONX1C5mRX4e43WuWRTnqLxBCIhZtKmbaI8sM06aEOiL
pw2iheaic1bvOFirw0uml6UBKwY6lpbvcSqg6AuD8rzCmWQsXULh8CdpLdVXLGz/x4Ft1n
f7rHzl1MD6T5+yXdAAAAC3JvdDI1NkBoZXhhAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDG1A2g2BDCkfyI1SYh3rJn+5MZg9CQFdVQpwJeUy9bYkj6j9EgzMYg3SGeJeIlvAarPjka9qhZBhZ4xxvfoVPEMm2aAG1Lg3IjHV2ilRqbXDoHbNkB4d9H4fvYta1q/+wIL7daTQSSo/lgas9zfCivMoIQa5NjPno58cs9hJxpGw==",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAxtQNoNgQwpH8iNUmId6yZ/uTGYPQkBXVUKcCXlMvW2JI+o/RIMzG
IN0hniXiJbwGqz45GvaoWQYWeMcb36FTxDJtmgBtS4NyIx1dopUam1w6B2zZAeHfR+H72L
Wtav/sCC+3Wk0EkqP5YGrPc3worzKCEGuTYz56OfHLPYScaRsAAAII40h81uNIfNYAAAAH
c3NoLXJzYQAAAIEAxtQNoNgQwpH8iNUmId6yZ/uTGYPQkBXVUKcCXlMvW2JI+o/RIMzGIN
0hniXiJbwGqz45GvaoWQYWeMcb36FTxDJtmgBtS4NyIx1dopUam1w6B2zZAeHfR+H72LWt
av/sCC+3Wk0EkqP5YGrPc3worzKCEGuTYz56OfHLPYScaRsAAAADAQABAAAAgDlCtLIPx7
PhSzM0/4hdlE+x+gktFxGH2CkkD+COYGMXCSFv7bBeiOjKBnZ/PoPThLAoeVW0l4Mb57jc
zsA2u+KQyo5ZW8ngpqbw+LK22C0UCUSsjOk14cWqta/robvtmGlIjlch/V7DEnwRfyIkAP
yokE109HS+oDQpls+oeYIxAAAAQQCHI3TY0O75nwszAZHleplQuPXCLHvvRSkd6l/JERkS
ZPz8LoPIW0oDtcLh9tpKcVWCm4ZuWuoDnlF46ozOU7WOAAAAQQDxk/uCeEsBikavYQe/Z3
S8bdPdHCu7jZZP4gjSBFmlBAkJmg+ZDCQC49ZaH1RwD+f6akQic4iGiN1wVMO8aoBfAAAA
QQDSsrrzHioWa5i5n1h15r97xJic7VfjfcgUbdEQpGF4lDBKVZy7O9VMyGaqE4wxIyixh1
hTn7WRDnw/Vydn/GDFAAAAC3JvdDI1NkBoZXhhAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGYImAgE51Zr2qgtm35nzY/88h9gYehjW9+CNa87mb5P",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBmCJgIBOdWa9qoLZt+Z82P/PIfYGHoY1vfgjWvO5m+TwAAAJA42+zRONvs
0QAAAAtzc2gtZWQyNTUxOQAAACBmCJgIBOdWa9qoLZt+Z82P/PIfYGHoY1vfgjWvO5m+Tw
AAAEC4yVHLE00IjntOw0ZPEvja/kDeiLgWQK4N+NQ4TKm4zGYImAgE51Zr2qgtm35nzY/8
8h9gYehjW9+CNa87mb5PAAAAC3JvdDI1NkBoZXhhAQI=
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOFmtb463zcFyZMdh23djtu2hQU5CUQHQKVwRkVMugOC",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDhZrW+Ot83BcmTHYdt3Y7btoUFOQlEB0ClcEZFTLoDggAAAJBrnHABa5xw
AQAAAAtzc2gtZWQyNTUxOQAAACDhZrW+Ot83BcmTHYdt3Y7btoUFOQlEB0ClcEZFTLoDgg
AAAEBYoBOpMvswZxK302oXzsfetRzdXD+BWRRCI9a4Kv6xweFmtb463zcFyZMdh23djtu2
hQU5CUQHQKVwRkVMugOCAAAAC3JvdDI1NkBoZXhhAQI=
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDOQPd+sUiGWMhnMe8umAxVc5GmGM0/OFJkTDIGecGbCAAAABHNzaDo=",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAABpzay1zc2
gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAACAzkD3frFIhljIZzHvLpgMVXORphjNPzhSZEwyB
nnBmwgAAAARzc2g6AAAA8BtxfCAbcXwgAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY2
9tAAAAIDOQPd+sUiGWMhnMe8umAxVc5GmGM0/OFJkTDIGecGbCAAAABHNzaDoBAAAAgFYp
IoE5Nk1NWUs5lsfr/weMX/RzF0C5I+5KezKhfBjpb4gAdFL0q2F1Kf/ltgXGq1Eg89JVLp
LlgWaGafO+JXzLfzdYzZrfYc73xEZTngk/j5DPcaDH1x6/YnBgU3TIEVzZf3demyZg7RSv
twHAN7bHDxJsv3WXRw/JjeRpgkiFAAAAAAAAAAtyb3QyNTZAaGV4YQECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyoeQnJJ6+OYB+oy8jshG3PM2cHQSqCtcnsEBxf2lqT0QTdw0u07neT09ZVqut3HdtZkSJ1+TfYxB3yX9M5nB0=",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMqHkJySevjmAfqMvI7IRtzzNnB0Eq
grXJ7BAcX9pak9EE3cNLtO53k9PWVarrdx3bWZEidfk32MQd8l/TOZwdAAAAqKcC7SGnAu
0hAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyoeQnJJ6+OYB+o
y8jshG3PM2cHQSqCtcnsEBxf2lqT0QTdw0u07neT09ZVqut3HdtZkSJ1+TfYxB3yX9M5nB
0AAAAgAqqeG68xdER0mnkNJ9QCx1cLQf+28ahmSX5WMO5wRcEAAAALcm90MjU2QGhleGEB
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----`,
	},
	testKeyPair{
		pk: "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGpdENH6L6VZFX21t8Rd2mDeQRa5jPhiFAE+EWrc+olJjNj7sjJIWm5AR6Gp+7NxfwEFf6h8rC96tk2Y1ik+UI4AAAAEc3NoOg==",
		sk: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAfwAAACJzay1lY2
RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAACG5pc3RwMjU2AAAAQQRqXRDR+i+l
WRV9tbfEXdpg3kEWuYz4YhQBPhFq3PqJSYzY+7IySFpuQEehqfuzcX8BBX+ofKwverZNmN
YpPlCOAAAABHNzaDoAAADguAETGLgBExgAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBv
cGVuc3NoLmNvbQAAAAhuaXN0cDI1NgAAAEEEal0Q0fovpVkVfbW3xF3aYN5BFrmM+GIUAT
4Ratz6iUmM2PuyMkhabkBHoan7s3F/AQV/qHysL3q2TZjWKT5QjgAAAARzc2g6AQAAAEDz
0O7gKVwW+fFf/yaf8eL2ukVRzRIUU0Dv2eXr8Ckhg2nT9f/eeWGICsV2Hm9VC0mKVyR3eJ
kPUeA+/gnFtKuWAAAAAAAAAAtyb3QyNTZAaGV4YQE=
-----END OPENSSH PRIVATE KEY-----`,
	},
}

func TestSignVerify(t *testing.T) {

	for rep := 0; rep < 50; rep++ {
		// copy keys
		keys := make([]testKeyPair, len(testKeys))
		copy(keys, testKeys)

		// shuffle the keys in the ring
		rand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })

		// decode keys
		sks := make([]KeyPair, 0, len(keys))
		pks := make([]PublicKey, 0, len(keys))
		for i := 0; i < len(testKeys); i++ {
			pk, err := PublicKeyFromStr(keys[i].pk)
			if err != nil {
				t.Error(err)
			}

			sk, err := ssh.ParseRawPrivateKey([]byte(keys[i].sk))
			if err != nil {
				sk = nil // -sk keys are not supported
			}

			pks = append(pks, pk)
			sks = append(
				sks,
				KeyPair{
					PK: pk,
					SK: sk,
				},
			)
		}

		msg := []byte("test")

		// pick the signing key in the ring
		var sk KeyPair
		for n := 0; sk.SK == nil; n++ {
			sk = sks[n]
		}

		t.Log(sk)
		t.Log(pks)

		sig := Sign(sk, pks, msg)

		_, err := sig.Verify(pks)
		if err != nil {
			t.Error(err)
		}

	}

}

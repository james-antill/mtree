package main

import (
	"fmt"
	"testing"
)

func TestAutoHashes(t *testing.T) {
	ah := autohashNew("md5", "djb2", "djb2a", "sha256", "shake-256-64")
	ah.Write([]byte("abcd"))

	data := []struct {
		chk string
		res string
	}{
		{"md5", "e2fc714c4727ee9395f324cd2e7f331f"},
		{"djb2", "7c93ee4f"},
		{"djb2a", "7c6d8341"},
		{"sha256", "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"},
		{"shake-256-64", "16c60651e6448eb9c177234fdd73ce60cbfe6d805c0e8f4c956986376be286d6787e6e2e0b8d1aeb7711e9a097cb592fc7043b5eb045d43afc1fae7b3aa2fa36"},
	}

	chks := ah.Checksums()
	for i := range data {
		chk := data[i].chk
		res := data[i].res

		if chk != chks[i].Kind {
			t.Errorf("chksum not equl:\n tst=<%s>\n got <%s>\n",
				chk, chks[i].Kind)
		}

		tst := fmt.Sprintf("%x", chks[i].Data)
		if res != fmt.Sprintf("%x", chks[i].Data) {
			t.Errorf("data not equl:\n tst=<%s>\n got <%s>\n",
				res, tst)
		}
	}

}

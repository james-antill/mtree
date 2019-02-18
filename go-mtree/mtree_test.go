package main

import (
	"os"
	"testing"
)

func TestFormat(t *testing.T) {
	data := []struct {
		val float64
		res string
	}{
		{0, "  0b "},
		{1, "  1b "},
		{2, "  2b "},
		{9, "  9b "},
		{10, " 10b "},
		{11, " 11b "},
		{99, " 99b "},
		{100, "100b "},
		{101, "101b "},
		{999, "999b "},

		{1000, "  1KB"},
		{1001, "1.0KB"},
		{1002, "1.0KB"},
		{1202, "1.2KB"},
		{9202, "9.2KB"},
		{9849, "9.8KB"},
		{9900, "9.9KB"},
		{9900, "9.9KB"},
		{9999, " 10KB"},
		{10000, " 10KB"},
		{10001, " 10KB"},
		{10022, " 10KB"},
		{10333, " 10KB"},
		{14444, " 14KB"},
		{19999, " 20KB"},

		{1000 * 1000, "  1MB"},
		{1000 * 1001, "1.0MB"},
		{1000 * 1002, "1.0MB"},
		{1000 * 1202, "1.2MB"},
		{1000 * 9202, "9.2MB"},
		{1000 * 9202, "9.2MB"},
		{1000 * 9849, "9.8MB"},
		{1000 * 9900, "9.9MB"},
		{1000 * 9900, "9.9MB"},
		{1000 * 9999, " 10MB"},
		{1000 * 10000, " 10MB"},
		{1000 * 10001, " 10MB"},
		{1000 * 10022, " 10MB"},
		{1000 * 10333, " 10MB"},
		{1000 * 14444, " 14MB"},
		{1000 * 19999, " 20MB"},
	}

	for i := range data {
		val := data[i].val
		res := data[i].res

		if tst := formatFKB(val); tst != res {
			t.Errorf("data not equl: %v\n tst=<%s>\n got <%s>\n",
				val, res, tst)
		}
	}

}

func TestPath(t *testing.T) {
	root := rootRes()
	d1 := newRes(root, "d1", os.ModeDir)
	d2 := newRes(root, "d2", os.ModeDir)
	d2n1 := newRes(d2, "n1", 0755)
	d3 := newRes(root, "d3", os.ModeDir)
	d3n1 := newRes(d3, "n1", 0755)
	d3n2 := newRes(d3, "n2", 0755)
	d4 := newRes(root, "d4", os.ModeDir)
	d4n1 := newRes(d4, "n1", 0755)
	d4n2 := newRes(d4, "n2", 0755)
	d4n3 := newRes(d4, "n3", 0755)
	d4n4 := newRes(d4, "n4", os.ModeDir)
	d4n4x1 := newRes(d4n4, "x1", 0755)

	d8 := ensureDir(root, "/a/b/c/d")
	dn4 := ensureDir(root, "/d4/n4")

	data := []struct {
		val string
		res string
	}{
		{d1.Path(), "/d1"},
		{d2.Path(), "/d2"},
		{d3.Path(), "/d3"},
		{d4.Path(), "/d4"},

		{d2n1.Path(), "/d2/n1"},

		{d3n1.Path(), "/d3/n1"},
		{d3n2.Path(), "/d3/n2"},

		{d4n1.Path(), "/d4/n1"},
		{d4n2.Path(), "/d4/n2"},
		{d4n3.Path(), "/d4/n3"},
		{d4n4.Path(), "/d4/n4"},

		{d4n4x1.Path(), "/d4/n4/x1"},

		{d8.Path(), "/a/b/c/d"},
		{dn4.Path(), "/d4/n4"},
	}

	for i := range data {
		val := data[i].val
		res := data[i].res

		if val != res {
			t.Errorf("data not equl:\n tst=<%s>\n got <%s>\n",
				res, val)
		}
	}
}

func TestHashes(t *testing.T) {
	data := []byte("some data to hash")
	res := "0f65fe41fc353e52c55667bb9e2b27bfcc8476f2c413e9437d272ee3194a4e3146d05ec04a25d16b8f577c19b82d16b1424c3e022e783d2b4da98de3658d363d"
	if ret := b2s(data2csum("shake-256-64", data)); ret != res {
		t.Errorf("data2csum->shake-256-64 is bad: %s !=\n %s\n",
			ret, res)
	}
	c := chkNew("shake-256-64")
	if ret := b2s(c.Sum(data)); ret != res {
		t.Errorf("chkNew->Sum->shake-256-64 is bad: %s !=\n %s\n",
			ret, res)
	}
	c.Write(data)
	if ret := b2s(c.Sum(nil)); ret != res {
		t.Errorf("chkNew->Write->shake-256-64 is bad: %s !=\n %s\n",
			ret, res)
	}
}

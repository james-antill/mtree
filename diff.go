package main

import (
	"bytes"
	"fmt"
	"io"
)

func iterMTd(r *MTnode, out chan<- *MTnode) {
	out <- r

	for _, c := range r.Children() {
		iterMTd(c, out)
	}
}

func iterMT(r *MTnode) <-chan *MTnode {
	ret := make(chan *MTnode)

	go func() { iterMTd(r, ret); close(ret) }()

	return ret
}

func cmpChksumEq(r1, r2 *MTnode) bool {
	dbg := false

	matched := false
	c1s := r1.csums[:]
	c2s := r2.csums[:]
	for len(c1s) > 0 && len(c2s) > 0 {
		c1 := c1s[0]
		c2 := c2s[0]

		if c1.Kind != c2.Kind {
			if dbg {
				fmt.Println("JDBG:", "skip", c1.Kind, c2.Kind)
			}
			if c1.Kind < c2.Kind {
				c1s = c1s[1:]
			} else {
				c2s = c2s[1:]
			}
			continue
		}

		if !bytes.Equal(c1.Data, c2.Data) {
			if dbg {
				fmt.Println("JDBG:", "data", r1.name, c1.Kind,
					b2s(r1.Checksum(c1.Kind)), b2s(r2.Checksum(c1.Kind)))
			}
			return false
		}
		if dbg {
			fmt.Println("JDBG:", "match", c1.Kind, c2.Kind)
		}
		matched = true // At least one checksum matched
		c1s = c1s[1:]
		c2s = c2s[1:]
	}

	return matched
}

type cbType int

const (
	cbAdd cbType = iota
	cbDel
	cbMod   // Gets the old value as an extra
	cbEqual // Gets the old value as an extra
)

func cbDiff(r1, r2 *MTnode, cb func(*MTnode, cbType, ...*MTnode)) {
	if cmpChksumEq(r1, r2) {
		cb(r2, cbEqual, r1)
	} else {
		cb(r2, cbMod, r1)
	}

	r1s := r1.Children()
	r2s := r2.Children()

	for len(r1s) > 0 && len(r2s) > 0 {
		i1 := r1s[0]
		i2 := r2s[0]

		if i1.name != i2.name {
			if fcmp(i1.name, i2.name) < 0 {
				cb(i1, cbDel)
				r1s = r1s[1:]
			} else {
				cb(i2, cbAdd)
				r2s = r2s[1:]
			}
			continue
		}

		if cmpChksumEq(i1, i2) {
			cb(i2, cbEqual, i1)
		} else if i1.IsDir() && i2.IsDir() {
			cbDiff(i1, i2, cb)
		} else {
			cb(i2, cbMod, i1)
		}

		r1s = r1s[1:]
		r2s = r2s[1:]
	}

	for _, i1 := range r1s {
		cb(i1, cbDel)
	}
	for _, i2 := range r2s {
		cb(i2, cbAdd)
	}
}

func prntDiff(w io.Writer, r1, r2 *MTnode, tree, ui bool) {
	cbDiff(r1, r2, func(n *MTnode, cbT cbType, on ...*MTnode) {
		switch cbT {
		case cbAdd:
			prntDiffMtree(w, n, tree, ui, "+", n.Size())
		case cbDel:
			prntDiffMtree(w, n, tree, ui, "-", n.Size())
		case cbMod:
			if false {
				prntListMtree(w, on[0], tree, ui, "-")
				prntListMtree(w, n, tree, ui, "+")
			} else {
				prntDiffMtree(w, n, tree, ui, "!", on[0].Size())
			}
		case cbEqual:
			prntDiffMtree(w, n, tree, ui, " ", n.Size())
		}
	})
}

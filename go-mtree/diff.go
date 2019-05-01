package main

import (
	"bytes"
	"fmt"
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

func prntDiff(r1, r2 *MTnode, tree, ui bool) {

	if cmpChksumEq(r1, r2) {
		prntListMtree(r1, tree, ui, " ")
	} else {
		prntListMtree(r1, tree, ui, "!")
	}

	r1s := r1.Children()
	r2s := r2.Children()

	for len(r1s) > 0 && len(r2s) > 0 {
		i1 := r1s[0]
		i2 := r2s[0]

		if i1.name != i2.name {
			if fcmp(i1.name, i2.name) < 0 {
				prntListMtree(i1, tree, ui, "-")
				r1s = r1s[1:]
			} else {
				prntListMtree(i2, tree, ui, "+")
				r2s = r2s[1:]
			}
			continue
		}

		if cmpChksumEq(i1, i2) {
			prntListMtree(i1, tree, ui, " ")
		} else if i1.IsDir() && i2.IsDir() {
			prntDiff(i1, i2, tree, ui)
		} else {
			prntListMtree(i2, tree, ui, "!")
		}

		r1s = r1s[1:]
		r2s = r2s[1:]
	}

	for _, i1 := range r1s {
		prntListMtree(i1, tree, ui, "-")
	}
	for _, i2 := range r2s {
		prntListMtree(i2, tree, ui, "+")
	}
}

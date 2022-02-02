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

// last is always based on r2, aka. new
func cbDiff(r1, r2 *MTnode, last []bool,
	cb func(*MTnode, cbType, []bool, ...*MTnode)) {
	if cmpChksumEq(r1, r2) {
		cb(r2, cbEqual, last, r1)
	} else {
		cb(r2, cbMod, last, r1)
	}

	r1s := r1.Children()
	r2s := r2.Children()

	// FIXME: Has to be a better way...
	nlast := append([]bool(nil), last...)
	nlast = append(nlast, false)

	for len(r1s) > 0 && len(r2s) > 0 {
		i1 := r1s[0]
		i2 := r2s[0]

		if i1.name != i2.name {
			if fcmp(i1.name, i2.name) < 0 {
				cb(i1, cbDel, nlast)
				r1s = r1s[1:]
			} else {
				cb(i2, cbAdd, nlast)
				r2s = r2s[1:]
			}
			continue
		}

		// Same name, so "same entry"
		if len(r1s) == 1 && len(r2s) == 1 {
			nlast[len(nlast)-1] = true
		}

		if cmpChksumEq(i1, i2) {
			cb(i2, cbEqual, nlast, i1)
		} else if i1.IsDir() && i2.IsDir() {
			cbDiff(i1, i2, nlast, cb)
		} else {
			cb(i2, cbMod, nlast, i1)
		}

		r1s = r1s[1:]
		r2s = r2s[1:]
	}

	for len(r1s) > 0 {
		i1 := r1s[0]
		if len(r2s) == 0 && len(r1s) == 1 {
			nlast[len(nlast)-1] = true
		}
		cb(i1, cbDel, nlast)
		r1s = r1s[1:]
	}
	for len(r2s) > 0 {
		i2 := r2s[0]
		if len(r2s) == 1 {
			nlast[len(nlast)-1] = true
		}
		cb(i2, cbAdd, nlast)
		r2s = r2s[1:]
	}
}

func prntDiff(w io.Writer, r1, r2 *MTnode, tree, ui bool) {
	// Chop the tree at the point we are showing the diff
	opr1 := r1.parent
	opr2 := r2.parent
	r1.parent = nil
	r2.parent = nil

	max1 := len(fmt.Sprintf("%d", r1.Size()))
	max2 := len(fmt.Sprintf("%d", r2.Size()))
	if max2 > max1 {
		max1 = max2
	}

	cbDiff(r1, r2, nil, func(n *MTnode, cbT cbType, last []bool, on ...*MTnode) {
		switch cbT {
		case cbAdd:
			prntDiffMtree(w, n, tree, last, ui, "+", n.Size(), max1)
		case cbDel:
			prntDiffMtree(w, n, tree, last, ui, "-", n.Size(), max1)
		case cbMod:
			if false {
				prntListMtree(w, on[0], tree, last, ui, "-", max1)
				prntListMtree(w, n, tree, last, ui, "+", max1)
			} else {
				prntDiffMtree(w, n, tree, last, ui, "!", on[0].Size(), max1)
			}
		case cbEqual:
			prntDiffMtree(w, n, tree, last, ui, " ", n.Size(), max1)
		}
	})
	// Restore the parents (and be nil
	r1.parent = opr1
	r2.parent = opr2
}

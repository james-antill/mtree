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
	// FIXME: False positives
	dbg := false

	if len(r1.csums) != len(r2.csums) {
		if dbg {
			fmt.Println("JDBG:", "len", r1.name, len(r1.csums), len(r2.csums))
			for i, k := range r1.csums {
				fmt.Println("JDBG:", "len r1:", i, k.Kind)
			}
			for i, k := range r2.csums {
				fmt.Println("JDBG:", "len r2:", i, k.Kind)
			}
		}
		return false
	}

	for i := range r1.csums {
		c1 := r1.csums[i]
		c2 := r2.csums[i]
		if c1.Kind != c2.Kind {
			if dbg {
				fmt.Println("JDBG:", "kind", r1.name, c1.Kind, c2.Kind)
			}
			return false
		}
		if !bytes.Equal(c1.Data, c2.Data) {
			if dbg {
				fmt.Println("JDBG:", "data", r1.name, c1.Kind,
					b2s(r1.Checksum(c1.Kind)), b2s(r2.Checksum(c1.Kind)))
			}
			return false
		}
	}

	return true
}

func prntDiff(r1, r2 *MTnode, tree, ui bool) {
	r1s := iterMT(r1)
	r2s := iterMT(r2)

	i1, ok1 := <-r1s
	i2, ok2 := <-r2s
	for ok1 && ok2 {
		if i1.name != i2.name {
			if fcmp(i1.name, i2.name) < 0 {
				prntListMtree(i1, tree, ui, "-")
				i1, ok1 = <-r1s
			} else {
				prntListMtree(i2, tree, ui, "+")
				i2, ok2 = <-r2s
			}
			continue
		}

		if cmpChksumEq(i1, i2) {
			prntListMtree(i1, tree, ui, " ")

		} else {
			prntListMtree(i2, tree, ui, "!")
		}

		i1, ok1 = <-r1s
		i2, ok2 = <-r2s
	}

	for i1 := range r1s {
		prntListMtree(i1, tree, ui, "-")
	}
	for i2 := range r2s {
		prntListMtree(i2, tree, ui, "+")
	}
}

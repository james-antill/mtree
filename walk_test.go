package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

const tstCleanup = false

const tstDirMax = 128
const tstFileMax = 128

func setupDirs(t *testing.T, prefix string) (int64, func()) {
	if err := os.RemoveAll(prefix); err != nil {
		t.Errorf("rmpath1(%s) error: %v\n", prefix, err)
	}

	var size int64

	limit := 32
	sem := make(chan int, limit)

	for i := 0; i < tstDirMax; i++ {
		dname := fmt.Sprintf("%s/%04d", prefix, i)
		if err := os.MkdirAll(dname, 0755); err != nil {
			t.Errorf("mkpath(%s) error: %v\n", dname, err)
		}

		for j := 0; j < tstFileMax; j++ {
			fname := fmt.Sprintf("%s/i%d-j%04d", dname, i, j)
			size += int64(len(fname))

			sem <- 0
			go func(j int) {
				defer func() { <-sem }()

				if err := ioutil.WriteFile(fname, []byte(fname),
					0777); err != nil {
					t.Errorf("writefile(%s) error: %v\n", fname, err)
				}
			}(j)
		}
	}

	for i := 0; i < limit; i++ {
		sem <- 0
	}
	close(sem)

	return size, func() {
		if !tstCleanup {
			return
		}

		sem := make(chan int, limit)

		for i := 0; i < tstDirMax; i++ {
			dname := fmt.Sprintf("%s/%04d", prefix, i)

			for j := 0; j < tstFileMax; j++ {
				fname := fmt.Sprintf("%s/i%d-j%04d", dname, i, j)

				sem <- 0
				go func(j int) {
					defer func() { <-sem }()

					if err := os.Remove(fname); err != nil {
						t.Errorf("rmfile(%s) error: %v\n", fname, err)
					}
				}(j)
			}

			if err := os.Remove(dname); err != nil {
				t.Errorf("rmdir(%s) error: %v\n", dname, err)
			}
		}

		for i := 0; i < limit; i++ {
			sem <- 0
		}
		close(sem)
	}
}

func TestWalk(t *testing.T) {
	trootPath := "testdata/foo"

	expectedSize, destroyDirs := setupDirs(t, trootPath)
	defer destroyDirs()

	numDigesters := 16
	filterNodes := false

	rootPath, err := normPath(trootPath)
	if err != nil {
		t.Errorf("path(%s) error: %v\n", trootPath, err)
	}

	rootNode, nodes, errc := walkFiles(rootPath, numDigesters, filterNodes)
	nodes = statNodes(nodes, numDigesters)
	// 		nodes = cacheNodes(nodes, numDigesters, cache, root+"/")
	//	nodes = digestNodes(nodes, numDigesters, 0, "")

	for r := range nodes {
		if r.err != nil {
			t.Errorf("node(%s) error: %v\n",
				r.Path(), r.err)
		}
	}

	if err := <-errc; err != nil {
		t.Errorf("main error: %v\n", err)
	}

	ret := ensureDir(rootNode, rootPath)
	ret.Checksum("md5") // Need to do it before we alter path.
	ret.parent = nil

	expectedNumNodes := tstDirMax * (tstFileMax + 1)
	if ret.Num() != expectedNumNodes {
		t.Errorf("bad num: %v\n got <%v>\n",
			expectedNumNodes, ret.Num())
	}

	if ret.Size() != expectedSize {
		t.Errorf("bad sz: %v\n got <%v>\n",
			expectedSize, ret.Size())
	}

	if tstDirMax != 128 || tstFileMax != 128 {
		return
	}

	md5 := fmt.Sprintf("%x", ret.Checksum("md5"))
	val := "1e18a81250da9bd08376afb21deb8c97"
	if md5 != val {
		t.Errorf("bad md5: %v\n got <%v>\n",
			val, md5)
	}
}

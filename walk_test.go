package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
)

const tstCleanup = false

const tstDirMax = 128
const tstFileMax = 128

func setupDirs(t *testing.T, prefix string) func() {
	if err := os.RemoveAll(prefix); err != nil {
		t.Errorf("rmpath1(%s) error: %v\n", prefix, err)
	}

	var wg sync.WaitGroup

	for i := 0; i < tstDirMax; i++ {
		dname := fmt.Sprintf("%s/%04d", prefix, i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := os.MkdirAll(dname, 0755); err != nil {
				t.Errorf("mkpath(%s) error: %v\n", dname, err)
			}

			for j := 0; j < tstFileMax; j++ {
				fname := fmt.Sprintf("%s/i%d-j%04d", dname, i, j)
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := ioutil.WriteFile(fname, []byte(fname),
						0777); err != nil {
						t.Errorf("writefile(%s) error: %v\n", fname, err)
					}
				}()
			}
		}()
	}

	wg.Wait()

	return func() {
		if !tstCleanup {
			return
		}

		if err := os.RemoveAll(prefix); err != nil {
			t.Errorf("rmpath2(%s) error: %v\n", prefix, err)
		}
	}
}

func TestWalk(t *testing.T) {
	trootPath := "testdata/foo"

	destroyDirs := setupDirs(t, trootPath)
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
	ret.parent = nil

	expectedNumNodes := tstDirMax * (tstFileMax + 1)
	if ret.Num() != expectedNumNodes {
		t.Errorf("bad num: %v\n got <%v>\n",
			expectedNumNodes, ret.Num())
	}
}

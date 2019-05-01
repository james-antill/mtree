package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func sstatDirExists(path string) bool {
	if fi, err := os.Stat(path); err == nil {
		return fi.IsDir()
	}
	return false
}

// findDotMtree returns the nearest .mtree from the given path, and the offset
// Eg. a/b/c/d/e might return a/b/.mtree, c/d/e
func findDotMtree(path string) (string, string) {
	root, _ := normPath(path)
	offset := ""
	for {
		dmtpath := root + "/.mtree"
		if sstatDirExists(dmtpath) {
			return dmtpath, offset
		}
		if root == "/" {
			break
		}

		if offset == "" {
			offset = filepath.Base(root)
		} else {
			offset = filepath.Base(root) + "/" + offset
		}
		root = filepath.Dir(root)
	}

	return "", ""
}

func latestMtree(dmt, path string) string {
	dmtl := dmt + "/local/"
	files, err := ioutil.ReadDir(dmtl)
	if err != nil {
		panic(err)
	}

	latest := ""
	for _, file := range files {
		fname := file.Name()
		switch {
		case strings.HasSuffix(fname, ".mtree"):
			latest = fname
		case strings.HasSuffix(fname, ".mtree.gz"):
			latest = fname
		case strings.HasSuffix(fname, ".mtree.bz2"):
			latest = fname
		case strings.HasSuffix(fname, ".mtree.xz"):
			latest = fname
		}
	}

	if latest == "" {
		fmt.Fprintln(os.Stderr, "Can't find a local snapshot from:", dmt)
		os.Exit(1)
	}

	return latest
}

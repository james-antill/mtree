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

func latestMtree(dir string) (string, error) {
	files, err := ioutil.ReadDir(dir) // Eh. wastes some resources...
	if err != nil {
		return "", err
	}

	latest := ""
	for _, file := range files { // This is sorted, so last is newest...
		fname := file.Name()

		// Format should be same as tmBaseName() ... need more checks.
		if len(fname) < len("2006-01-02--1504Z.mtree") {
			continue
		}

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
		return "", fmt.Errorf("Can't find a local snapshot from: %s", dir)
	}

	return latest, nil
}

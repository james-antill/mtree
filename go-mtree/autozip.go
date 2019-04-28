package main

import (
	"compress/bzip2"
	"compress/gzip"
	"io/ioutil"

	"github.com/ulikunitz/xz"

	"io"
	"strings"
)

func autounzip(data io.Reader, filename string) (io.ReadCloser, error) {
	var zr io.ReadCloser
	var err error

	switch {
	case strings.HasSuffix(filename, ".gz"):
		zr, err = gzip.NewReader(data)
	case strings.HasSuffix(filename, ".bz2"):
		zr = ioutil.NopCloser(bzip2.NewReader(data))
	case strings.HasSuffix(filename, ".xz"):
		var tzr io.Reader
		tzr, err = xz.NewReader(data)
		zr = ioutil.NopCloser(tzr)
	default:
		zr = ioutil.NopCloser(data)
	}

	return zr, err
}

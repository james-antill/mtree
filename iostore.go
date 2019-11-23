package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	roc "github.com/james-antill/rename-on-close"
)

func storeNodeType(r *MTnode) byte {
	if r.IsSymlink() {
		return 'l'
	} else if r.IsDir() {
		return 'd'
	} else {
		return 'f'
	}
}

func storeWriteFileNode(iow io.Writer, r *MTnode) {
	fn := r.Path()

	fmt.Fprintf(iow, "P: %c %d %s\n", storeNodeType(r), len(fn), fn)

	for _, csum := range calcChecksumKinds {
		fmt.Fprintf(iow, "C-%s: %s\n", csum, b2s(r.Checksum(csum)))
	}

	fmt.Fprintf(iow, "%s %d\n", "S:", r.Size())

	timeFmt := ".000000000"
	tm := r.LatestModTime()
	if tm.Nanosecond() == 0 {
		fmt.Fprintf(iow, "%s %d\n", "MT:", tm.Unix())
	} else {
		fmt.Fprintf(iow, "%s %d%s\n", "MT:", tm.Unix(), tm.Format(timeFmt))
	}
}

func storeWriteFileDir(iow io.Writer, r *MTnode) {
	leafOnly := false
	if !leafOnly || !r.IsDir() || len(r.children) == 0 {
		storeWriteFileNode(iow, r)
	}

	if !r.IsDir() {
		return
	}

	for _, c := range r.Children() {
		storeWriteFileDir(iow, c)
	}
}

func storeWriteFile(iow io.Writer, r *MTnode) {
	fmt.Fprintf(iow, "mtree-file-0.2\n")
	storeWriteFileDir(iow, r)
}

func atoi(s string) (int64, error) {
	i64, err := strconv.ParseInt(s, 10, 64)
	return i64, err
}

// MtreeFile loads an mtree froma file.
func MtreeFile(mfname string, progress bool) (*MTnode, error) {
	file, err := os.Open(mfname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	npath, err := normPath(mfname) // ????
	if err != nil {
		return nil, err
	}

	zr, err := autounzip(file, npath)
	if err != nil {
	}
	defer zr.Close()

	scanner := bufio.NewScanner(zr)
	if !scanner.Scan() {
		switch scanner.Text() {
		case "mtree-file-0.1":
			fallthrough
		case "mtree-file-0.2":
			break
		default:
			return nil, fmt.Errorf("Invalid mtree file: %s", mfname)
		}
	}

	root := rootRes()
	var hasRoot = false

	pparent := ""
	ppent := root

	var cur *MTnode

	for scanner.Scan() {
		txt := scanner.Text()
		switch {
		case strings.HasPrefix(txt, "P: "): // Path
			tsp := txt[3:]
			tsps := strings.SplitN(tsp, " ", 3)
			if len(tsps) != 3 {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}
			ftype, sizeStr, wpath := tsps[0], tsps[1], tsps[2]

			var mode os.FileMode
			switch ftype {
			case "d":
				mode = os.ModeDir
			case "f": // zero case is regular file.
			case "l":
				mode = os.ModeSymlink
			default:
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}

			size, err := atoi(sizeStr)
			if err != nil {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}

			for size > int64(len(wpath)) {
				if !scanner.Scan() {
					return nil, fmt.Errorf("Corrupt mtree file: %s near %s",
						mfname, txt)
				}
				wpath += "\n" + scanner.Text()
			}
			if wpath[0] == '/' {
				hasRoot = true
			} else { // Shouldn't be a mix in a single file.
				wpath = "/" + wpath
			}

			ppent, pparent = ensureParentDir(root, wpath, pparent, ppent)
			name := path.Base(wpath)
			cur = newRes(ppent, name, mode)

		case false && strings.HasPrefix(txt, "D: "): // Data
			tsp := txt[3:]
			tsps := strings.SplitN(tsp, " ", 2)
			if len(tsps) != 2 {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}
			sizeStr, wData := tsps[0], tsps[1]

			size, err := atoi(sizeStr)
			if err != nil {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}

			for size > int64(len(wData)) {
				if !scanner.Scan() {
					return nil, fmt.Errorf("Corrupt mtree file: %s near %s",
						mfname, txt)
				}
				wData += "\n" + scanner.Text()
			}
			// cur.data = wData

		case strings.HasPrefix(txt, "MT: "): // Modified Time
			modtimeLine := txt[4:]
			sns := strings.SplitN(modtimeLine, ".", 2)
			secs, err := atoi(sns[0])
			if err != nil {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}
			var nsecs int64
			if len(sns) == 2 {
				nsecs, err = atoi(sns[1])
				if err != nil {
					return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
						mfname, txt)
				}
			}
			nsecs += secs * 1000000000
			cur.mtimeNsecs = nsecs

		case strings.HasPrefix(txt, "S: "): // Size
			sizeStr := txt[3:]
			size, err := atoi(sizeStr)
			if err != nil {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}
			cur.size = size

		case strings.HasPrefix(txt, "C-"): // Checksums
			ckd := txt[2:]
			ckds := strings.SplitN(ckd, ": ", 2)
			if len(ckds) != 2 {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}
			if cur.IsDir() {
				continue // FIXME: Have the directory checksums re-resolve.
			}
			chkKind, chkDataStr := ckds[0], ckds[1]
			chkData, err := hex.DecodeString(chkDataStr)
			if err != nil {
				return nil, fmt.Errorf("Corrupt mtree file: %s near: %s",
					mfname, txt)
			}

			csum := Checksum{Kind: chkKind, Data: chkData}
			cur.csums = append(cur.csums, csum)

			// case strings.HasPrefix(txt, "AT: "): // access time
			// case strings.HasPrefix(txt, "CT: "): // ctime
			// case strings.HasPrefix(txt, "MO: "): /// Mode
			// case strings.HasPrefix(txt, "Num: "):
			// case strings.HasPrefix(txt, "U: "): // Uid
			// case strings.HasPrefix(txt, "G: "): // Gid
			// case strings.HasPrefix(txt, "D: "): // Device
			// case strings.HasPrefix(txt, "I: "): // Inode
			// case strings.HasPrefix(txt, "L: "): // Links (number of)
			// default: warn?
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if !hasRoot {
		if len(root.children) != 1 {
			return nil, fmt.Errorf("Bad .mtree file: %s: No data found",
				mfname)
		}
		root.children[0].parent = nil
		root = root.children[0]
	}

	// Regenerate directory checksums from the files...
	for _, csum := range validChecksumKinds {
		root.Checksum(csum)
	}

	return root, nil

}

func tmBaseName(tm time.Time) string {
	// In old speak: "%Y-%m-%d--%H%MZ
	return tm.Format("2006-01-02--1504Z")
}

func hasSuffixMtree(name string) bool {
	switch {
	case strings.HasSuffix(name, ".mtree.bz2"):
		fallthrough
	case strings.HasSuffix(name, ".mtree.gz"):
		fallthrough
	case strings.HasSuffix(name, ".mtree.xz"):
		fallthrough
	case strings.HasSuffix(name, ".mtree"):
		return true
	}
	return false
}

func latestSnapshot(dmt string, flagProgress bool) (string, error) {
	// Find the latest snapshot file from a given .mtree dir...
	mh, err := MtreeFile(dmt+"/HEAD", flagProgress)
	if err != nil {
		// FIXME: Error.Wrap
		return "", fmt.Errorf("Can't load .mtree/HEAD from: %s (%v)", dmt, err)
	}
	mh, _ = mtreeChdir(mh, "local")
	mh.parent = nil // Kind of hacky atm. ... for Path()
	var mhl *MTnode

	for _, n := range mh.Children() {
		if hasSuffixMtree(n.Name()) {
			mhl = n
			break
		}
	}
	if mhl == nil {
		return "", fmt.Errorf("Can't load .mtree/HEAD from: %s", dmt)
	}

	return mhl.Name(), nil
}

func latestCache(dmt string) (string, error) {
	dmtc := dmt + "/cache/"
	fname, err := latestMtree(dmtc)
	if err != nil {
		return "", err
	}

	return fname, nil
}

func storeWriteDataSymlink(dmt, ndmt, ndfn string, r *MTnode) error {
	if err := os.MkdirAll(dmt, 0770); err != nil {
		return err
	}

	fo, err := roc.Create(ndmt)
	if err != nil {
		return err
	}
	defer fo.Close()

	// FIXME: Race with MtreePath() and not efficient

	data, err := os.Readlink(ndfn)
	if err != nil { // Ignore read errors
		fmt.Fprintln(os.Stderr, "data:", ndfn, err)
		return nil
	}

	if _, err := fo.WriteString(data); err != nil {
		return err
	}

	if err := fo.CloseRename(); err != nil {
		return err
	}
	return nil
}

// storeWriteData writes the data for the non-regular files to the .mtree/data
// dmt: path to the .mtree/data/<foo>
// dfn: path to the FS (parent of mtree)
func storeWriteData(dmt, dfn string, r *MTnode) error {
	ndmt := dmt + "/" + r.name
	ndfn := dfn + "/" + r.name

	if r.IsSymlink() { // Atm. just symlink data
		return storeWriteDataSymlink(dmt, ndmt, ndfn, r)
	}

	if !r.IsDir() {
		return nil
	}

	for _, c := range r.Children() {
		if err := storeWriteData(ndmt, ndfn, c); err != nil {
			return err
		}
	}

	return nil
}

func storeWriteDotMtree(dmt, prefix string, saveData bool,
	mtree *MTnode) (string, error) {
	bfn := tmBaseName(time.Now().UTC())

	if saveData {
		sdfn := dmt + "/data/" + bfn
		dtree := path.Dir(path.Dir(dmt))
		if err := storeWriteData(sdfn, dtree, mtree); err != nil {
			fmt.Println("JDBG:", err)
			return "", err
		}
	}

	nfn := dmt + prefix + bfn + ".mtree"
	fo, err := roc.Create(nfn)
	if err != nil {
		fmt.Println("JDBG:", err)
		return "", err
	}
	defer fo.Close()

	iow := bufio.NewWriter(fo)
	storeWriteFile(iow, mtree)
	if err := iow.Flush(); err != nil {
		fmt.Println("JDBG:", err)
		return "", err
	}
	if err := fo.CloseRename(); err != nil {
		fmt.Println("JDBG:", err)
		return "", err
	}

	return bfn, nil
}

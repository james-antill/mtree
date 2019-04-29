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
)

func storeWriteNode(iow io.Writer, r *MTnode) {
	fn := r.Path()

	if r.IsSymlink() {
		fmt.Fprintf(iow, "P: l %d %s\n", len(fn), fn)
	} else if r.IsDir() {
		fmt.Fprintf(iow, "P: d %d %s\n", len(fn), fn)
	} else {
		fmt.Fprintf(iow, "P: f %d %s\n", len(fn), fn)
	}

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

func storeWriteDir(iow io.Writer, r *MTnode) {
	leafOnly := false
	if !leafOnly || !r.IsDir() || len(r.children) == 0 {
		storeWriteNode(iow, r)
	}

	if !r.IsDir() {
		return
	}

	for _, c := range r.Children() {
		storeWriteDir(iow, c)
	}
}

func storeWriteFile(iow io.Writer, r *MTnode) {
	fmt.Fprintf(iow, "mtree-file-0.2\n")
	storeWriteDir(iow, r)
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
				wpath += scanner.Text()
			}
			if wpath[0] == '/' {
				hasRoot = true
			} else { // Shouldn't be a mix in a single file.
				wpath = "/" + wpath
			}

			ppent, pparent = ensureParentDir(root, wpath, pparent, ppent)
			name := path.Base(wpath)
			cur = newRes(ppent, name, mode)

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
			panic(root)
		}
		if !root.children[0].IsDir() {
			panic(root)
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

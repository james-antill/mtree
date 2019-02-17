package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/karrick/godirwalk"

	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

// Checksum is a holder for different checksums
type Checksum struct {
	Kind string
	Data []byte
}

func (chk Checksum) String() string {
	return fmt.Sprintf("%s:%s", chk.Kind, chk.Data)
}

// A MTnode is the part fo the merkle tree for a file.
type MTnode struct {
	name       string
	parent     *MTnode
	csums      []Checksum
	mode       os.FileMode
	size       int64
	mtimeNsecs int64
	children   []*MTnode
	err        error
}

// Name of the node
func (r *MTnode) Name() string {
	return r.name
}

// IsDir returns true if the node is a directory
func (r *MTnode) IsDir() bool {
	return r.mode.IsDir()
}

// IsSymlink returns true if the node is a symlink
func (r *MTnode) IsSymlink() bool {
	return r.mode&os.ModeSymlink != 0
}

// IsRegular returns true if the node is a regular file
func (r *MTnode) IsRegular() bool {
	return r.mode.IsRegular()
}

func fcmp(a, b string) int {
	if len(a) == len(b) {
		return bytes.Compare([]byte(a), []byte(b))
	}

	return len(a) - len(b)
}
func fcmpLess(a, b string) bool {
	if fcmp(a, b) < 0 {
		return true
	}
	return false
}

// add a child to a parent
func (r *MTnode) add(c *MTnode) {
	r.children = append(r.children, c)
	sort.Slice(r.children, func(i, j int) bool {

		return fcmpLess(r.children[i].name, r.children[j].name)
	})
	r.csums = nil
}

// No "shake-256-64" because it requires work to make it act like a normal hash
var validChecksumKinds = [...]string{"md5", "sha1", "sha256", "sha3-256", "sha3-512"}

// var calcChecksumKinds = validChecksumKinds[:]
var calcChecksumKinds = []string{"md5", "sha1", "sha256", "sha3-256"}
var primaryChecksum = "md5"
var primaryChecksumUILen = 16

func validChecksum(kind string) bool {
	csums := validChecksumKinds

	// Check it's an apporved checksum
	for _, csum := range csums {
		if csum == kind {
			return true
		}
	}
	return false

}

func checksumSymlink(r *MTnode, kind string) {
	// Currently do all the checksums for files...
	csums := calcChecksumKinds

	path := r.path()

	data, err := os.Readlink(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		data = ""
	}
	r.size = int64(len(data))

	r.csums = nil
	for _, csum := range csums {
		c := data2csum(csum, []byte(data))
		r.csums = append(r.csums, Checksum{csum, c})
	}

}

func checksumFile(r *MTnode, kind string) {
	// Currently do all the checksums for files...
	csums := calcChecksumKinds

	path := r.path()

	ior, err := os.Open(path)
	if err != nil {
		r.err = err
		return
	}
	defer ior.Close()

	chks := []hash.Hash{}
	chksio := []io.Writer{}
	for _, csum := range csums {
		c := chkNew(csum)
		chks = append(chks, c)
		chksio = append(chksio, c)
	}

	iow := io.MultiWriter(chksio...)

	written, err := io.Copy(iow, ior)
	if err != nil {
		r.err = err
		return
	}
	r.size = written

	r.csums = nil
	for i, csum := range csums {
		r.csums = append(r.csums, Checksum{csum, chks[i].Sum(nil)})
	}
}

// Checksum gives the hash of the directory and all children
func (r *MTnode) Checksum(kind string) []byte {
	if !validChecksum(kind) {
		return nil
	}

	for _, csum := range r.csums {
		if csum.Kind == kind {
			return csum.Data
		}
	}

	// Files/symlinks get done in go procs.

	// Is a file/symlink...
	// Checksum the data within the file...
	if r.IsSymlink() {
		checksumSymlink(r, kind)
		return r.Checksum(kind)
	} else if !r.IsDir() {
		checksumFile(r, kind)
		if r.err != nil {
			c := data2csum(kind, []byte{})
			r.csums = append(r.csums, Checksum{kind, c})
			return c
		}
		return r.Checksum(kind)
	}

	// Is a directory...
	// just merge all the data from all the children...
	dd := ""
	for _, child := range r.children {
		dd += child.name
		dd += " "
		// FIXME: hex.Encode?
		dd += fmt.Sprintf("%x", child.Checksum(kind))
		dd += "\n"
	}

	c := data2csum(kind, []byte(dd))
	r.csums = append(r.csums, Checksum{kind, c})
	return c
}

// Size gives the size of the directory and all children, not overflow safe.
func (r *MTnode) Size() int64 {
	num := r.size
	for _, child := range r.children {
		num += child.Size()
	}
	return num
}

func (r *MTnode) latestModNSecs() int64 {
	mtime := r.mtimeNsecs
	for _, child := range r.children {
		if lmtime := child.latestModNSecs(); lmtime > mtime {
			mtime = lmtime
		}
	}
	return mtime
}

// LatestModTime gives the newest mtime of the directory and all children.
func (r *MTnode) LatestModTime() time.Time {
	return time.Unix(0, r.latestModNSecs())
}

// Depth gives the number of children in the directory and all children
func (r *MTnode) Depth() int {
	if r.parent == nil {
		return 0
	}
	return r.parent.Depth() + 1
}

func (r *MTnode) dpath() string {
	if !r.IsDir() {
		panic(r)
	}
	if r.parent == nil {
		if r.name == "/" {
			return r.name
		}
		return r.name + "/"
	}
	if r.name == "/" {
		panic(r)
	}
	return r.parent.dpath() + r.name + "/"
}

func (r *MTnode) num() int {
	num := len(r.children)
	for _, child := range r.children {
		num += child.num()
	}
	return num
}

func (r *MTnode) path() string {
	if r.parent == nil {
		return r.name
	}
	if r.name == "/" {
		panic(r)
	}
	return r.parent.dpath() + r.name
}

func newRes(dres *MTnode, base string, mode os.FileMode) *MTnode {
	res := &MTnode{name: base, parent: dres, mode: mode}
	if dres != nil && res.name == "/" {
		panic(res)
	}
	if res.name == "." {
		panic(res)
	}
	if dres != nil {
		dres.add(res)
	}
	//	fmt.Println("nres:", res.path())
	return res
}

func ensureDir(m map[string]*MTnode, p string) *MTnode {

	if res, ok := m[p]; ok {
		return res
	}

	dres := getDirRes(m, p)
	res := newRes(dres, path.Base(p), os.ModeDir)
	m[res.path()] = res
	return res
}

func getDirRes(m map[string]*MTnode, p string) *MTnode {
	if p == "." {
		p, _ = os.Getwd()
	}
	if p == "/" {
		return nil
	}

	//	fmt.Println("path:", p)
	dp := path.Dir(p)
	return ensureDir(m, dp)
}

// walkFiles starts a goroutine to walk the directory tree at root and send the
// node of each file to the node channel.  It sends the result of the
// walk on the error channel.  If done is closed, walkFiles abandons its work.
// qlen sets the buffer on the nodes channel.
func walkFiles(done <-chan struct{}, wroot string, qlen int,
	needCachingData bool) (<-chan *MTnode, <-chan error) {

	nodes := make(chan *MTnode, qlen)
	errc := make(chan error, 1)
	go func() {
		// Close the channel after Walk returns.
		defer close(nodes)

		root := make(map[string]*MTnode)
		var err error
		if wroot, err = filepath.Abs(wroot); err != nil {
			panic(err)
		}

		if _, err := os.Stat(wroot); err != nil {
			errc <- err
			return
		}

		errc <- godirwalk.Walk(wroot, &godirwalk.Options{
			Unsorted: true, // faster, yet non-deterministic enumeration
			Callback: func(path string, de *godirwalk.Dirent) error {
				//		errc <- filepath.Walk(wroot, func(path string, info os.FileInfo, err error) error {
				//				if err != nil {
				//					return nil // Ignore errors or fail on perm. denied?
				//				}

				//				mode := info.Mode()
				mode := de
				if mode.IsSymlink() { // Due to windows symlink+dir
				} else if mode.IsDir() {
					ensureDir(root, path)
					return nil
				} else if !mode.IsRegular() {
					return nil
				}

				dp := getDirRes(root, path)
				// de.Name() == path.Base(path)
				res := newRes(dp, de.Name(), mode.ModeType())

				if needCachingData {
					if fi, err := os.Lstat(path); err == nil {
						res.mtimeNsecs = fi.ModTime().UnixNano()
					}
					// FIXME: If it's wanted, fill in uid/etc.
				}

				select {
				case nodes <- res:
				case <-done:
					return errors.New("walk canceled")
				}
				return nil
			},
		})
		nodes <- root["/"]
	}()

	return nodes, errc
}

// ShakeSum256_64 is a 64 byte output version of ShakeSum256
func ShakeSum256_64(data []byte) [64]byte {
	var ret [64]byte
	sha3.ShakeSum256(ret[:], data)
	return ret
}

func data2csum(csum string, data []byte) []byte {
	switch csum {
	case "md5":
		val := md5.Sum(data)
		return val[:]
	case "sha1":
		val := sha1.Sum(data)
		return val[:]
	case "sha256":
		val := sha256.Sum256(data)
		return val[:]
	case "sha512":
		val := sha512.Sum512(data)
		return val[:]
	case "sha3-256":
		val := sha3.Sum256(data)
		return val[:]
	case "sha3-512":
		val := sha3.Sum512(data)
		return val[:]
		//	case "shake-256-64":
		//		val := ShakeSum256_64(data)
		//		return val[:]
	default:
		panic("Bad csum" + csum)
	}
}

func chkNew(csum string) hash.Hash {
	switch csum {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "sha3-256":
		return sha3.New256()

		// FIXME: missing shake
	default:
		panic("Bad csum" + csum)
	}
}

// digester gets nodes for files/symlinks and creates the checksum data for them.
func digester(done <-chan struct{}, paths <-chan *MTnode, c chan<- *MTnode) {
	for res := range paths {
		if res == nil {
			panic("res is nil")
		}

		if res.name == "/" {
			// Should be the last one...
			select {
			case c <- res:
			case <-done:
				return
			}
		}

		if res.IsRegular() {
			checksumFile(res, "")
		} else if res.IsSymlink() {
			checksumSymlink(res, "")
		}

		select {
		case c <- res:
		case <-done:
			return
		}
	}
}

func first(r *MTnode) *MTnode {
	if r == nil {
		return r
	}

	if len(r.children) != 1 {
		return r
	}
	if !r.children[0].IsDir() {
		return r
	}
	return first(r.children[0])
}

var numCPUWorkers = 0

// Mtree Generate for root path
func Mtree(root string, needCachingData bool) (*MTnode, error) {
	done := make(chan struct{})
	defer close(done)

	numDigesters := numCPUWorkers
	if numDigesters < 1 {
		numDigesters = runtime.NumCPU()
	}
	if numDigesters < 1 {
		numDigesters = 1
	}

	nodes, errc := walkFiles(done, root, numDigesters, needCachingData)

	c := make(chan *MTnode)

	var wg sync.WaitGroup

	wg.Add(numDigesters)
	for i := 0; i < numDigesters; i++ {
		go func() {
			digester(done, nodes, c)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	var ret *MTnode
	for r := range c {
		if r.err != nil {
			fmt.Fprintln(os.Stderr, r.err)
		}
		if r.name == "/" {
			ret = r
		}
	}
	ret = first(ret) // Skip the usuless root nodes

	// Check whether the Walk failed.
	if err := <-errc; err != nil { // HLerrc
		return nil, err
	}
	return ret, nil
}

// UI names for KiloBytes etc.
const (
	KB = 1000
	MB = KB * 1000
	GB = MB * 1000
	TB = GB * 1000
)

// round use like so: "%.1f", round(f, 0.1) or "%.0f", round(f, 1)
// Otherwise 9.9999 is < 10 but "%.1f" will give "10.0"
func round(x, unit float64) float64 {
	return float64(int64(x/unit+0.5)) * unit
}

// What we want is useful level of information. Eg.
// 999b
// 1.2KB
//  22KB
// 222KB
// 1.2MB

func fmtSprint(f float64, ext string) string {
	rf := round(f, 0.1)
	if f == float64(int(f)) || rf >= 10 {
		return fmt.Sprintf("%3d%s", int(rf), ext)
	}
	return fmt.Sprintf("%.1f%s", rf, ext)
}

func formatFKB(f float64) string {
	ext := "b "
	switch {
	case f >= TB:
		f /= TB
		ext = "TB"
	case f >= GB:
		f /= GB
		ext = "GB"
	case f >= MB:
		f /= MB
		ext = "MB"
	case f >= KB:
		f /= KB
		ext = "KB"
	}
	return fmtSprint(f, ext)
}
func formatKB(i int64) string {
	return formatFKB(float64(i))
}

func _muin(ui bool, size int64) string {
	if !ui {
		return fmt.Sprintf("%d", size)
	}
	return formatKB(size)
}

func b2s(b []byte) string {
	return fmt.Sprintf("%x", b)
}

func prntListMtree(r *MTnode, tree, ui bool, sizePrefix string) {

	chksum := b2s(r.Checksum(primaryChecksum))
	if ui && primaryChecksumUILen > 0 {
		chksum = chksum[:primaryChecksumUILen]
	}

	fn := r.path()

	if tree {
		if r.Depth() == 0 {
			fn = r.name
		} else {
			indent := strings.Repeat(" |  ", r.Depth()-1) + " \\_ "
			fn = indent + r.name
		}
	}
	if ui && r.IsDir() && r.parent != nil {
		fn = fn + "/"
	}

	fmt.Printf("%s %s%s %s\n", chksum, sizePrefix, _muin(ui, r.Size()), fn)
}

func prntListMtreed(r *MTnode, tree, ui bool, sizePrefix string) {
	leafOnly := false
	if !leafOnly || !r.IsDir() || r.num() == 0 {
		prntListMtree(r, tree, ui, sizePrefix)
	}

	if !r.IsDir() {
		return
	}

	for _, c := range r.children {
		prntListMtreed(c, tree, ui, sizePrefix)
	}
}

func main() {
	var flagPChecksum string
	var flagFast bool
	var flagUI bool
	var flagNUI bool
	flag.BoolVar(&flagUI, "ui", false, "Use UI output")
	flag.BoolVar(&flagNUI, "no-ui", false, "Use UI output")
	flag.BoolVar(&flagFast, "fast", false, "Only calc. primary checksum")
	flag.IntVar(&primaryChecksumUILen, "ui-checksum-length",
		primaryChecksumUILen, "length of UI display checksum")
	flag.StringVar(&flagPChecksum, "checksums", primaryChecksum, "what checksums to display/use")
	flag.IntVar(&numCPUWorkers, "workers",
		primaryChecksumUILen, "manually set number of checksum workers")
	flag.Parse()

	if flagNUI {
		flagUI = false
	} else {
		if !flagUI {
			if terminal.IsTerminal(int(os.Stdout.Fd())) {
				flagUI = true
			}
		}
	}

	if validChecksum(flagPChecksum) {
		primaryChecksum = flagPChecksum
	}

	if flagFast {
		calcChecksumKinds = []string{primaryChecksum}
	}

	if len(flag.Args()) != 2 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// FIXME: Using flagFast is a massive hack here. Add caching first ;)
	m, err := Mtree(flag.Arg(1), !flagFast)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "directory-ls":
		fallthrough
	case "directory-list":
		fallthrough
	case "dir-ls":
		fallthrough
	case "dir-list":
		fallthrough
	case "ls":
		fallthrough
	case "list":
		p := m.parent
		m.parent = nil
		prntListMtreed(m, false, flagUI, "")
		m.parent = p
	case "directory-tree":
	case "dir-tree":
	case "tree":
		p := m.parent
		m.parent = nil
		prntListMtreed(m, true, flagUI, "")
		m.parent = p

	case "directory-sum":
		fallthrough
	case "dir-sum":
		fallthrough
	case "directory-summary":
		fallthrough
	case "dir-summary":
		fallthrough
	case "sum":
		fallthrough
	case "summary":
		fmt.Println("Name:", m.path())
		fmt.Println("  Num     :", m.num())
		fmt.Println("  Size    :", m.Size())
		fmt.Println("  Mod Time:", m.LatestModTime())
		mchks := 0
		for _, csum := range calcChecksumKinds {
			if len(csum) > mchks {
				mchks = len(csum)
			}
		}
		for _, csum := range calcChecksumKinds {
			fmt.Printf("    %-*s: %s\n", 4+mchks, "Chk-"+csum,
				b2s(m.Checksum(csum)))
		}

	default:
		fmt.Println("Usage: mtree list|summary|tree <dir>")
		os.Exit(1)
	}
}

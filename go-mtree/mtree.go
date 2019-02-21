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

	"github.com/james-antill/mpb"
	"github.com/james-antill/mpb/decor"

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

	sorted bool
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

// Children gives you the sorted children of this node.
func (r *MTnode) Children() []*MTnode {
	if !r.sorted {
		sort.Slice(r.children, func(i, j int) bool {
			return fcmpLess(r.children[i].name, r.children[j].name)
		})
		r.sorted = true
	}

	return r.children
}

// add a child to a parent
func (r *MTnode) add(c *MTnode) {
	r.children = append(r.children, c)
	r.sorted = false
	r.csums = nil
}

// var calcChecksumKinds = validChecksumKinds[:]
var calcChecksumKinds = []string{"md5", "sha1", "sha256"}
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

	path := r.Path()

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

	path := r.Path()

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

const hextable = "0123456789abcdef"

// Checksum gives the hash of the directory and all children
func (r *MTnode) Checksum(kind string) []byte {
	for _, csum := range r.csums {
		if csum.Kind == kind {
			return csum.Data
		}
	}

	if !validChecksum(kind) {
		return nil
	}

	// Files/symlinks get done in go procs. and combine all caclChecksums
	// but we still have code here anyway for future.

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
	// merge all the data from all the children...

	// For large sets this can be slow, so parallel ftw.
	var wg sync.WaitGroup
	for _, child := range r.Children() {
		if !child.IsDir() {
			continue
		}
		wg.Add(1)
		go func(c *MTnode) {
			defer wg.Done()
			c.Checksum(kind)
		}(child)
	}
	wg.Wait()

	var dd bytes.Buffer
	for _, child := range r.Children() {
		dd.WriteString(child.name)
		dd.WriteByte(' ')
		chk := child.Checksum(kind)
		//		dd += fmt.Sprintf("%x", chk)
		for _, b := range chk {
			dd.WriteByte(hextable[b>>4])
			dd.WriteByte(hextable[b&0x0f])
		}
		dd.WriteByte('\n')
	}

	c := data2csum(kind, dd.Bytes())
	r.csums = append(r.csums, Checksum{kind, c})
	// Recurse so we know it's cached...
	// return c
	return r.Checksum(kind)
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

// Depth gives the depth from the root of the child, 0 == root.
func (r *MTnode) Depth() int {
	if r.parent == nil {
		return 0
	}
	return r.parent.Depth() + 1
}

// Num gives the number of children in the directory and all children, not overflow safe.
func (r *MTnode) Num() int {
	num := len(r.children)
	for _, child := range r.children {
		num += child.Num()
	}
	return num
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

// Path gives the full path to the node
func (r *MTnode) Path() string {
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
	if res.name == "" {
		panic(res)
	}
	if dres != nil {
		dres.add(res)
	}
	//	fmt.Println("nres:", res.path())
	return res
}

func rootRes() *MTnode {
	return newRes(nil, "/", os.ModeDir)
}

func lookupDirRes(d *MTnode, n string) *MTnode {
	if !d.sorted || len(d.children) <= 10 { // Brute force for small entries
		for _, c := range d.children {
			if c.name != n {
				continue
			}
			return c
		}
		return nil
	}

	// Now be clever...
	ents := d.Children()
	i := sort.Search(len(ents), func(i int) bool {
		return fcmpLess(n, ents[i].name)
	})
	if i < len(ents) && ents[i].name == n {
		return ents[i]
	}
	return nil
}

func lookupRes(root *MTnode, p []string) (*MTnode, int) {
	d := root
	num := 0
	for _, n := range p {
		nd := lookupDirRes(d, n)
		if nd == nil {
			break
		}
		num++
		d = nd
	}

	return d, num
}

func ensureDirEnts(root *MTnode, pents []string) *MTnode {
	d, num := lookupRes(root, pents)
	if len(pents) == num {
		return d
	}

	for _, name := range pents[num:] {
		d = newRes(d, name, os.ModeDir)
	}

	return d
}

func pathSplit(p string) []string {
	pents := strings.Split(p, "/")
	if pents[0] != "" {
		panic(p)
	}
	return pents[1:]
}
func ensureDir(root *MTnode, p string) *MTnode {
	return ensureDirEnts(root, pathSplit(p))
}

func ensureParentDir(root *MTnode,
	p, pparent string, ppent *MTnode) (*MTnode, string) {
	d := path.Dir(p)
	if d == pparent {
		return ppent, pparent
	}

	// Sort the old directory so we can do fast lookups?
	// walk does depth first though, so it's not great.
	if false && ppent != nil {
		// Slower on 2,000 / 100
		// Slower on 200 / 1,000
		ppent.Children()
	}
	pents := pathSplit(p)
	ppents := pents[:len(pents)-1]
	return ensureDirEnts(root, ppents), d
}

// FIXME: Needs to config. this...
func filterName(name string) bool {
	if strings.HasSuffix(name, "~") {
		return true
	}
	if strings.HasSuffix(name, ".bak") {
		return true
	}
	if strings.HasSuffix(name, ".swp") {
		return true
	}

	if name == ".git" {
		return true
	}
	if name == ".mtree" {
		return true
	}

	return false
}

// FileMode is a wrapper around os.FileMode that implements .IsSymlink()
type FileMode struct{ os.FileMode }

// IsSymlink reports whether m describes a directory. That is, it tests for the ModeSymlink bit being set in m.
func (m FileMode) IsSymlink() bool {
	return (m.FileMode & os.ModeSymlink) != 0
}

// walkFiles starts a goroutine to walk the directory tree at root and send the
// node of each file to the node channel.  It sends the result of the
// walk on the error channel.  If done is closed, walkFiles abandons its work.
// qlen sets the buffer on the nodes channel.
func walkFiles(done <-chan struct{}, wroot string, qlen int,
	needCachingData, filter, progress bool) (<-chan *MTnode, int64, <-chan error) {

	nodes := make(chan *MTnode, qlen)
	errc := make(chan error, 1)
	go func() {
		// Close the channel after Walk returns.
		defer close(nodes)

		var err error
		if wroot, err = filepath.Abs(wroot); err != nil {
			panic(err)
		}

		if fi, err := os.Lstat(wroot); err == nil {
			hfi := FileMode{fi.Mode()}
			if hfi.IsSymlink() {
				nr, err := filepath.EvalSymlinks(wroot)
				if err != nil {
					errc <- err
					return
				}
				wroot = nr
			}
		}

		if _, err := os.Stat(wroot); err != nil {
			errc <- err
			return
		}

		root := rootRes()

		//		fmt.Println("JDBG: BEG:", time.Now())
		pparent := ""
		ppent := root
		errc <- godirwalk.Walk(wroot, &godirwalk.Options{
			Unsorted: true, // faster, yet non-deterministic enumeration
			Callback: func(p string, de *godirwalk.Dirent) error {
				//		errc <- filepath.Walk(wroot, func(path string, info os.FileInfo, err error) error {
				//				if err != nil {
				//					return nil // Ignore errors or fail on perm. denied?
				//				}

				//				mode := info.Mode()
				//				name := path.Base(path)
				mode := de
				name := de.Name()
				// de.Name() == path.Base(p)

				if filter && filterName(name) {
					if mode.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if mode.IsSymlink() { // Due to windows symlink+dir
				} else if mode.IsDir() { // Because of empty dirs.
					// ppent, pparent = ensureParentDir(root, p+"/.", pparent, ppent)
					ensureDir(root, p)
					return nil
				} else if !mode.IsRegular() {
					return nil
				}

				ppent, pparent = ensureParentDir(root, p, pparent, ppent)
				res := newRes(ppent, name, mode.ModeType())

				if needCachingData {
					if fi, err := os.Lstat(p); err == nil {
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
			// We can't do this because
			//			PostChildrenCallback: func(p string, de *godirwalk.Dirent) error {
			//				res := ensureDir(root, p)
			//				res.dirDone()
			//			},
		})
		nodes <- root
		//		fmt.Println("JDBG: END:", time.Now())
	}()

	// NOTE: This is sometimes faster and sometimes slower??
	if progress {
		nnodes := make(chan *MTnode, qlen)
		lennodes := make(chan int64)

		go func() {
			h := []*MTnode{}
			for n := range nodes {
				h = append(h, n)
			}
			lennodes <- int64(len(h))
			for _, n := range h {
				nnodes <- n
			}
			close(nnodes)
		}()

		return nnodes, <-lennodes, errc
	}
	return nodes, 0, errc
}

// ShakeHash convert to normal golang hases...
type shake2hash32 struct {
	shake sha3.ShakeHash
}
type shake2hash64 struct {
	shake sha3.ShakeHash
}

// Pass through fuctions...
func (s *shake2hash32) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}
func (s *shake2hash32) Read(p []byte) (n int, err error) {
	return s.shake.Read(p)
}
func (s *shake2hash32) Reset() {
	s.shake.Reset()
}
func (s *shake2hash32) BlockSize() int {
	return 4096
}
func (s *shake2hash64) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}
func (s *shake2hash64) Read(p []byte) (n int, err error) {
	return s.shake.Read(p)
}
func (s *shake2hash64) Reset() {
	s.shake.Reset()
}
func (s *shake2hash64) BlockSize() int {
	return 4096
}

// Different 32/64 functions...
func (s *shake2hash32) Clone() sha3.ShakeHash {
	return &shake2hash32{s.shake.Clone()}
}
func (s *shake2hash32) Size() int {
	return 32
}
func (s *shake2hash32) Sum(b []byte) []byte {
	ns := s.shake.Clone()

	var ret [32]byte
	ns.Write(b)
	ns.Read(ret[:])
	return ret[:]
}

func (s *shake2hash64) Clone() sha3.ShakeHash {
	return &shake2hash64{s.shake.Clone()}
}
func (s *shake2hash64) Size() int {
	return 64
}
func (s *shake2hash64) Sum(b []byte) []byte {
	ns := s.shake.Clone()

	var ret [64]byte
	ns.Write(b)
	ns.Read(ret[:])
	return ret[:]
}

// No Sum32/Sum64 ?

// ShakeSum128_32 is a 32 byte output version of ShakeSum128
func ShakeSum128_32(data []byte) [32]byte {
	var ret [32]byte
	sha3.ShakeSum256(ret[:], data)
	return ret
}

// ShakeSum256_64 is a 64 byte output version of ShakeSum256
func ShakeSum256_64(data []byte) [64]byte {
	var ret [64]byte
	sha3.ShakeSum256(ret[:], data)
	return ret
}

var validChecksumKinds = [...]string{"md5", "sha1",
	"sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256",
	"sha3-224", "sha3-256", "sha3-384", "sha3-512",
	"shake-128-32", "shake-256-64"}

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
	case "sha384":
		val := sha512.Sum384(data)
		return val[:]
	case "sha512":
		val := sha512.Sum512(data)
		return val[:]
	case "sha512-224":
		val := sha512.Sum512_224(data)
		return val[:]
	case "sha512-256":
		val := sha512.Sum512_256(data)
		return val[:]

	case "sha3-224":
		val := sha3.Sum224(data)
		return val[:]
	case "sha3-256":
		val := sha3.Sum256(data)
		return val[:]
	case "sha3-384":
		val := sha3.Sum384(data)
		return val[:]
	case "sha3-512":
		val := sha3.Sum512(data)
		return val[:]

	case "shake-128-32":
		val := ShakeSum128_32(data)
		return val[:]
	case "shake-256-64":
		val := ShakeSum256_64(data)
		return val[:]

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
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	case "sha512-224":
		return sha512.New512_224()
	case "sha512-256":
		return sha512.New512_256()

	case "sha3-224":
		return sha3.New224()
	case "sha3-256":
		return sha3.New256()
	case "sha3-384":
		return sha3.New384()
	case "sha3-512":
		return sha3.New512()

	case "shake-128-32":
		return &shake2hash32{sha3.NewShake128()}
	case "shake-256-64":
		return &shake2hash64{sha3.NewShake256()}
	default:
		panic("Bad csum" + csum)
	}
}

// digester gets nodes for files/symlinks and creates the checksum data for them.
func digester(done <-chan struct{}, paths <-chan *MTnode, c chan<- *MTnode,
	dbar *mpb.Bar) {
	for res := range paths {

		if res == nil {
			panic("res is nil")
		}

		if res.name == "/" {
			if dbar != nil {
				dbar.Increment()
			}
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

		if dbar != nil {
			dbar.Increment()
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
func Mtree(root string, needCachingData, filter, progress bool) (*MTnode, error) {
	done := make(chan struct{})
	defer close(done)

	numDigesters := numCPUWorkers
	if numDigesters < 1 {
		numDigesters = runtime.NumCPU()
	}
	if numDigesters < 1 {
		numDigesters = 1
	}

	nodes, nnodes, errc := walkFiles(done, root, numDigesters,
		needCachingData, filter, progress)

	c := make(chan *MTnode)

	var wg sync.WaitGroup

	var p *mpb.Progress
	var dbar *mpb.Bar
	if progress {
		p = mpb.New(mpb.WithWaitGroup(&wg))
		dbar = p.AddBarDef(nnodes, "Digest: ", decor.Unit_k)
	}
	wg.Add(numDigesters)
	for i := 0; i < numDigesters; i++ {
		go func() {
			digester(done, nodes, c, dbar)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		if p != nil {
			p.Stop()
		}
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
	primaryChecksum := calcChecksumKinds[0]
	chksum := b2s(r.Checksum(primaryChecksum))
	if ui && primaryChecksumUILen > 0 {
		chksum = chksum[:primaryChecksumUILen]
	}

	fn := r.Path()

	if tree {
		depth := r.Depth()
		if depth == 0 {
			fn = r.name
		} else {
			indent := strings.Repeat(" |  ", depth-1) + " \\_ "
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
	if !leafOnly || !r.IsDir() || len(r.children) == 0 {
		prntListMtree(r, tree, ui, sizePrefix)
	}

	if !r.IsDir() {
		return
	}

	for _, c := range r.Children() {
		prntListMtreed(c, tree, ui, sizePrefix)
	}
}

func main() {
	var flagHelp bool
	helpUsage := "show help"
	flag.BoolVar(&flagHelp, "help", false, helpUsage)
	flag.BoolVar(&flagHelp, "h", false, helpUsage+" (shorthand)")

	var flagPChecksum string
	var flagFast bool
	var flagProgress bool
	var flagFilter bool
	var flagUI bool

	isTermOut := terminal.IsTerminal(int(os.Stdout.Fd()))
	isTermErr := terminal.IsTerminal(int(os.Stderr.Fd()))

	flag.BoolVar(&flagUI, "ui", isTermOut, "Use UI output")
	flag.BoolVar(&flagFast, "fast", false, "Only calc. primary checksum")
	progUsage := "show progress bar"
	flag.BoolVar(&flagProgress, "progress", isTermErr, progUsage)
	flag.BoolVar(&flagProgress, "p", isTermErr, progUsage+" (shorthand)")
	flag.BoolVar(&flagFilter, "filter", true, "filter useless entries")
	flag.IntVar(&primaryChecksumUILen, "ui-checksum-length",
		primaryChecksumUILen, "length of UI display checksum")
	pchkDef := "md5,sha1,sha256,shake-256-64"
	flag.StringVar(&flagPChecksum, "checksums", pchkDef, "what checksums to display/use")
	flag.IntVar(&numCPUWorkers, "workers",
		primaryChecksumUILen, "manually set number of checksum workers")
	flag.Parse()

	if flagPChecksum != "" {
		f := func(c rune) bool {
			switch c {
			case ';':
				return true
			case ',':
				return true
			case ':':
				return true
			case '/':
				return true
			case ' ':
				return true
			case '\t':
				return true
			default:
				return false
			}
		}
		calcChecksumKinds = []string{}
		for _, csum := range strings.FieldsFunc(flagPChecksum, f) {
			if validChecksum(csum) {
				calcChecksumKinds = append(calcChecksumKinds, csum)
			}
		}
	}

	if flagFast {
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
		case "directory-tree":
		case "dir-tree":
		case "tree":
			calcChecksumKinds = calcChecksumKinds[:1]
		default:
		}
	}

	// FIXME: Using flagFast is a massive hack here. Add caching first ;)
	cachingData := !flagFast

	switch flag.Arg(0) {
	case "chk":
		fallthrough
	case "check":
		if flagHelp || len(flag.Args()) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: mtree check <dir> <check> [check...]")
			flag.PrintDefaults()
			if flagHelp {
				os.Exit(0)
			}
			os.Exit(1)
		}

	default:
		if flagHelp || len(flag.Args()) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: mtree check|list|summary|tree <dir> [check...]")
			flag.PrintDefaults()
			if flagHelp {
				os.Exit(0)
			}
			os.Exit(1)
		}
	}

	m, err := Mtree(flag.Arg(1), cachingData, flagFilter, flagProgress)
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
		fmt.Println("Name:", m.Path())
		fmt.Println("  Num     :", m.Num())
		fmt.Println("  Size    :", m.Size())
		if cachingData {
			fmt.Println("  Mod Time:", m.LatestModTime())
		}
		mchks := 0
		for _, csum := range calcChecksumKinds {
			if len(csum) > mchks {
				mchks = len(csum)
			}
		}
		for _, csum := range calcChecksumKinds {
			// Cache dir. checksum so it doesn't stop in the middle of the line
			m.Checksum(csum)
			fmt.Printf("    %-*s: %s\n", 4+mchks, "Chk-"+csum,
				b2s(m.Checksum(csum)))
		}

	case "chk":
		fallthrough
	case "check":
		chkArgs := flag.Args()[2:]
		chkDone := make([]bool, len(chkArgs))
		for _, csum := range calcChecksumKinds {
			for i, arg := range chkArgs {
				if len(arg) < (len(csum) + 2) {
					continue
				}
				if !strings.HasPrefix(arg, csum+":") {
					continue
				}

				argCsum := arg[len(csum)+1:]
				fndCsum := b2s(m.Checksum(csum))
				if !strings.HasPrefix(fndCsum, argCsum) {
					fmt.Fprintln(os.Stderr, "Failed checksum:", csum)
					os.Exit(4)
				}
				chkDone[i] = true
			}
		}

		for i, chk := range chkDone {
			if chk {
				continue
			}

			fmt.Fprintln(os.Stderr, "No match for checksum:", chkArgs[i])
			os.Exit(4)
		}

	default:
		fmt.Fprintln(os.Stderr, "Usage: mtree check|list|summary|tree <dir> [checks...]")
		os.Exit(1)
	}
}

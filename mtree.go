package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	// "github.com/saracen/walker"
	walker "github.com/karrick/godirwalk"

	"github.com/james-antill/mpb"
	"github.com/james-antill/mpb/decor"
	roc "github.com/james-antill/rename-on-close"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/pkg/sftp"

	"gopkg.in/ini.v1"
)

// Checksum is a holder for different checksums
type Checksum struct {
	Kind string
	Data []byte
}

func (chk Checksum) String() string {
	return fmt.Sprintf("%s:%s", chk.Kind, chk.Data)
}

var numCPUWorkers = 0

func numCPUDigesters() int {
	numDigesters := numCPUWorkers
	if numDigesters < 1 {
		numDigesters = runtime.NumCPU()
	}
	if numDigesters >= 1 {
		numDigesters *= 2
	} else {
		numDigesters = 2
	}

	return numDigesters
}

// MTnode is the common part of the merkle tree for a file/dir/symlink.
type MTnode struct {
	name       string
	parent     *MTnode
	csums      []Checksum
	size       int64     // Only useful for !isDir
	mtimeNsecs int64     // Only useful for !isDir
	children   []*MTnode // Only useful for  isDir
	err        error     // Only useful during walk
	// data       []byte    // For non-regular files?

	fsActive bool // Can we call into the FS to get checksums

	sorted bool

	isDir     bool
	isSymlink bool
}

// Name of the node
func (r *MTnode) Name() string {
	return r.name
}

// IsDir returns true if the node is a directory
func (r *MTnode) IsDir() bool {
	return r.isDir
}

// IsSymlink returns true if the node is a symlink
func (r *MTnode) IsSymlink() bool {
	return r.isSymlink // .mode&os.ModeSymlink != 0
}

// IsRegular returns true if the node is a regular file
func (r *MTnode) IsRegular() bool {
	return !r.isDir && !r.isSymlink
}

// ChildrenUnsorted of the node
func (r *MTnode) ChildrenUnsorted() []*MTnode {
	if !r.isDir {
		return nil
	}
	return r.children
}

func fcmp(a, b string) int {
	if len(a) == len(b) {
		return bytes.Compare([]byte(a), []byte(b))
	}

	return len(a) - len(b)
}
func fcmpLessEq(a, b string) bool {
	if fcmp(a, b) <= 0 {
		return true
	}
	return false
}

// Children gives you the sorted children of this node.
func (r *MTnode) Children() []*MTnode {
	if !r.sorted {
		sort.Slice(r.children, func(i, j int) bool {
			return fcmpLessEq(r.children[i].name, r.children[j].name)
		})
		r.sorted = true
	}

	return r.children
}

// Reset the checksums of the node, and all parents
func (r *MTnode) Reset() {
	r.sorted = false
	r.csums = nil
	r.size = 0
	if r.parent != nil {
		r.parent.Reset()
	}
}

// Add a child to a parent
func (r *MTnode) Add(c *MTnode) {
	r.children = append(r.children, c)
	if r.sorted {
		r.Reset()
	}
}

// Replace a Child a parent
func (r *MTnode) Replace(c *MTnode) bool {
	ents := r.Children()
	i := sort.Search(len(ents), func(i int) bool {
		return fcmpLessEq(c.name, ents[i].name)
	})
	if i < len(ents) && ents[i].name == c.name {
		ents[i] = c
		c.parent = r
		r.Reset()
		return true
	}

	r.Add(c)
	c.parent = r
	return false
}

// calcChecksumKinds is the checksums we want to calculate on the data.
var calcChecksumKinds = []string{"md5", "sha1", "sha256",
	"murmur3-128", "shake-256-64"}

// calcChecksumKindPrimary is the checksum we want when we are only using one.
var calcChecksumKindPrimary = "sha256"

// calcChecksumsReset empties the list of checksums we'll calculate, must add
// at least one
func calcChecksumsReset() {
	calcChecksumKinds = []string{}
	calcChecksumKindPrimary = ""
}

// calcChecksumsAdd adds a new checksum to what we'll calculate
func calcChecksumsAdd(chksum string) bool {
	if !validChecksum(chksum) {
		return false
	}

	if calcChecksumKindPrimary == "" {
		calcChecksumKindPrimary = chksum
	}

	for _, ochksum := range calcChecksumKinds {
		if chksum == ochksum {
			return false
		}
	}

	calcChecksumKinds = append(calcChecksumKinds, chksum)
	return true
}

// calcChecksumsDone sorts the checksums
func calcChecksumsDone() {
	if calcChecksumKindPrimary == "" {
		panic("calcChecksumKindPrimary is unset")
	}
	sort.Strings(calcChecksumKinds)
}

// calcChecksumsUI produces ordered output for initialization UI, where the
// first argument is the primary.
func calcChecksumsUI() []string {
	calcChecksumsDone()

	ocsums := make([]string, len(calcChecksumKinds))
	ocsums = ocsums[0:0]
	ocsums = append(ocsums, calcChecksumKindPrimary)
	for _, chksum := range calcChecksumKinds {
		if chksum == calcChecksumKindPrimary {
			continue
		}
		ocsums = append(ocsums, chksum)
	}

	return ocsums
}

// uiChecksumLen is how much of the checksum we show when we want to be smaller
var uiChecksumLen = 16

func checksumSymlink(r *MTnode, kind string) {
	// Currently do all the checksums for files...
	csums := calcChecksumKinds

	path := r.Path()

	data, err := os.Readlink(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		data = ""
	}
	// r.data = data
	r.size = int64(len(data))

	r.csums = nil
	for _, csum := range csums {
		c := data2csum(csum, []byte(data))
		r.csums = append(r.csums, Checksum{csum, c})
	}

}

func checksumFile(r *MTnode, kind string) {
	// Currently do all the checksums for files...

	path := r.Path()

	ior, err := os.Open(path)
	if err != nil {
		r.err = err
		return
	}
	defer ior.Close()

	ah := autohashNew(calcChecksumKinds...)

	written, err := io.Copy(ah, ior)
	if err != nil {
		r.err = err
		return
	}
	r.size = written

	r.csums = ah.Checksums()
}

const hextable = "0123456789abcdef"

func bytes2hex(dd *bytes.Buffer, data []byte) {
	//		dd += fmt.Sprintf("%x", data)
	for _, b := range data {
		dd.WriteByte(hextable[b>>4])
		dd.WriteByte(hextable[b&0x0f])
	}

}

func (r *MTnode) findCsum(kind string) *Checksum {
	for i := range r.csums {
		v := &r.csums[i]
		if v.Kind == kind {
			return v
		}
	}
	return nil
}

func (r *MTnode) childrenEmptyChecksum(kind string, d chan<- *MTnode) {
	if r.findCsum(kind) != nil {
		return
	}

	if r.IsDir() {
		for _, child := range r.Children() {
			child.childrenEmptyChecksum(kind, d)
		}
		return
	}

	d <- r
}

func (r *MTnode) childrenSetupChecksums(kind string, limit int) chan<- *MTnode {
	if limit <= 0 {
		limit = numCPUDigesters()
	}

	sem := make(chan int, limit) // Use optional workers
	data := make(chan *MTnode)
	go func() {
		defer close(data)
		r.childrenEmptyChecksum(kind, data)
	}()

	for c := range data {
		sem <- 0
		go func(child *MTnode) {
			child.Checksum(kind)
			<-sem
		}(c)
	}

	for i := 0; i < limit; i++ {
		sem <- 0
	}
	return data
}

const assumeAveNameLen = 12
const assumeAveNameNumLen = 2 // log10()+1 ... 6 = 1, 66 = 2, 666 = 3, ...

// dirBytesChildren1 to serialize just the name of the data and the checksum.
func dirBytesChildren1(dd *bytes.Buffer,
	r *MTnode, kind string) *bytes.Buffer {
	perChild := assumeAveNameLen
	perChild++
	perChild += chkSize(kind) * 2
	dd.Grow(len(r.children) * perChild)

	for _, child := range r.Children() {
		dd.WriteString(child.name)
		dd.WriteByte(' ')
		chk := child.Checksum(kind)
		if chk == nil {
			return nil
		}
		bytes2hex(dd, chk)
		dd.WriteByte('\n')
	}

	return dd
}

// dirBytesChildren2 to serialize the type of the node too,
// so file => symlink transitions change. We also make it parseable.
func dirBytesChildren2(dd *bytes.Buffer,
	r *MTnode, kind string) *bytes.Buffer {
	perChild := assumeAveNameNumLen
	perChild += assumeAveNameLen
	perChild += 4
	perChild += chkSize(kind) * 2
	dd.Grow(len(r.children) * perChild)

	for _, child := range r.Children() {
		dd.WriteString(strconv.Itoa(len(child.name)))
		dd.WriteByte(' ')
		dd.WriteString(child.name)
		dd.WriteByte(' ')
		dd.WriteByte(storeNodeType(child))
		dd.WriteByte(' ')
		chk := child.Checksum(kind)
		if chk == nil {
			return nil
		}
		bytes2hex(dd, chk)
		dd.WriteByte('\n')
	}

	return dd
}

const originalSerialize = true

func dirBytesChildren(dd *bytes.Buffer,
	r *MTnode, kind string) *bytes.Buffer {
	if originalSerialize {
		return dirBytesChildren1(dd, r, kind)
	}

	return dirBytesChildren2(dd, r, kind)
}

// Checksum gives the hash of the directory and all children
func (r *MTnode) Checksum(kind string) []byte {
	if kind == "" {
		kind = calcChecksumKindPrimary
	}

	for _, csum := range r.csums {
		if csum.Kind == kind {
			return csum.Data
		}
	}

	if !validChecksum(kind) {
		return nil
	}

	// Is a file/symlink...
	// Checksum the data within the file...
	if r.IsSymlink() {
		if !r.fsActive {
			return nil
		}
		checksumSymlink(r, kind)
		return r.Checksum(kind)
	} else if !r.IsDir() {
		if !r.fsActive {
			return nil
		}
		checksumFile(r, kind)
		if r.err != nil {
			c := data2csum(kind, []byte{})
			return c
		}
		return r.Checksum(kind)
	}

	// Is a directory...
	// merge all the data from all the children...

	// For large sets this can be slow, so parallel when we need to.
	// FIXME: This is a bit spewy in some cases: cached files, deep dirs.
	// r.childrenSetupChecksums(kind, 0)

	var dd bytes.Buffer
	dirBytesChildren(&dd, r, kind)
	c := data2csum(kind, dd.Bytes())
	r.csums = append(r.csums, Checksum{kind, c})
	// Recurse so we know it's cached...
	// return c
	return r.Checksum(kind)
}

// Size gives the size of the directory and all children, not overflow safe.
func (r *MTnode) Size() int64 {
	num := r.size
	if num > 0 {
		return num
	}

	for _, child := range r.children {
		num += child.Size()
	}

	r.size = num // Cache directory sizes...

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

// dpathLen is the length of allocation needed for dpath()
func (r *MTnode) dpathLen() int {
	if !r.IsDir() {
		panic(r)
	}

	ret := len(r.name)
	if r.parent != nil {
		ret += r.parent.dpathLen()
	}
	if r.name != "/" {
		ret++
	}

	return ret
}

// dpath is the directory path of the node, should only be called on dirs.
func (r *MTnode) dpath(b *strings.Builder) {
	if !r.IsDir() {
		panic(r)
	}

	if r.parent != nil {
		if r.name == "/" {
			panic(r)
		}
		r.parent.dpath(b)
	}

	b.WriteString(r.name)
	if r.name == "/" { // Don't double /
		return
	}
	b.WriteByte('/')
}

// Path gives the full path to the node
func (r *MTnode) Path() string {
	if r.parent == nil {
		return r.name
	}
	if r.name == "/" {
		panic(r)
	}

	var b strings.Builder
	b.Grow(r.parent.dpathLen() + len(r.name))
	r.parent.dpath(&b)
	b.WriteString(r.name)
	return b.String()
}

func isSymlink(mode os.FileMode) bool {
	return mode&os.ModeSymlink != 0
}

func newRes(dres *MTnode, base string, mode os.FileMode) *MTnode {
	res := &MTnode{name: base, parent: dres,
		isDir: mode.IsDir(), isSymlink: isSymlink(mode)}
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
		res.fsActive = dres.fsActive
		dres.Add(res)
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
		return fcmpLessEq(n, ents[i].name)
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

func mtreeChdir(node *MTnode, path string) (*MTnode, error) {
	// pents := pathSplit(path)
	pents := strings.Split(path, "/")

	d, num := lookupRes(node, pents)
	if len(pents) == num {
		return d, nil
	}
	return nil, fmt.Errorf("Path not found: %s", path)
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

// mustAbs calls filepath.Abs() and panics if there is an error
func mustAbs(path string) string {
	ret, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return ret
}

func normPath(root string) (string, error) {
	root = mustAbs(root)

	fi, err := os.Lstat(root)
	if err != nil {
		return "", err
	}

	hfi := FileMode{fi.Mode()}
	if hfi.IsSymlink() {
		nr, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", err
		}
		return nr, nil
	}

	return root, nil
}

// walkFiles starts a goroutine to walk the directory tree at root and send the
// node of each file to the node channel.  It sends the result of the
// walk on the error channel.  If done is closed, walkFiles abandons its work.
// qlen sets the buffer on the nodes channel.
func walkFiles(wroot string, qlen int,
	filter bool) (*MTnode, <-chan *MTnode, <-chan error) {

	nodes := make(chan *MTnode, qlen)
	errc := make(chan error, 1)

	root := rootRes()
	root.fsActive = true

	go func() {
		// Close the channel after Walk returns.
		defer close(nodes)

		rootFI, err := os.Stat(wroot)
		if err != nil {
			errc <- err
			return
		}

		if !rootFI.IsDir() {
			ppent, _ := ensureParentDir(root, wroot, "", root)
			name := path.Base(wroot)
			res := newRes(ppent, name, rootFI.Mode())
			nodes <- res
			nodes <- root
			errc <- nil
			return
		}

		// Timing the walk...
		// fmt.Println("JDBG: BEG:", time.Now())
		// defer func() { fmt.Println("JDBG: END:", time.Now()) }()

		pparent := ""
		ppent := root
		nodeCB := func(p string, de *walker.Dirent) error {
			mode := de
			name := de.Name()
			//		var mux sync.Mutex
			//		nodeCB := func(p string, fi os.FileInfo) error {
			//			mux.Lock()
			//			defer mux.Unlock()

			//			mode := fi.Mode()
			//			name := fi.Name()

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
			// ppent, pparent = ensureParentDir(root, p, "", root)
			res := newRes(ppent, name, mode.ModeType())

			nodes <- res
			//				select {
			//				case nodes <- res:
			//				case <-done:
			//					return errors.New("walk canceled")
			//				}
			return nil
		}

		errCB := func(p string, e error) walker.ErrorAction {
			//		errCB := func(p string, e error) error {
			ensureParentDir(root, p, pparent, ppent)
			fmt.Fprintln(os.Stderr, e)
			return walker.SkipNode
			//			return nil
		}

		// Walker
		// errc <- walker.Walk(wroot, nodeCB, walker.WithErrorCallback(errCB))

		// Godirwalk
		errc <- walker.Walk(wroot, &walker.Options{
			Unsorted:      true, // faster, yet non-deterministic enumeration
			Callback:      nodeCB,
			ErrorCallback: errCB,
			//  We can't do this because we don't know when the checksum workers
			// will be finished with the child nodes.
			//			PostChildrenCallback: func(p string, de *godirwalk.Dirent) error {
			//				res := ensureDir(root, p)
			//				res.dirDone()
			//			},
		})
	}()

	return root, nodes, errc
}

func statNode(res *MTnode) {
	p := res.Path()
	if fi, err := os.Lstat(p); err == nil {
		res.mtimeNsecs = fi.ModTime().UnixNano()
		res.size = fi.Size() // Note that this is filled in by digest, but
		// it's required for caching to work.
	}
	// FIXME: If it's wanted, fill in uid/etc.
}

// statNodes gets each node and stat()s to get the mtime, keeps order the same.
func statNodes(nodes <-chan *MTnode, qlen int) <-chan *MTnode {
	statNodes := make(chan *MTnode, qlen)

	var wg sync.WaitGroup
	wg.Add(qlen)

	for i := 0; i < qlen; i++ {
		go func() {
			for res := range nodes {
				statNode(res)
				statNodes <- res
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(statNodes)
	}()

	return statNodes
}

func chksumKindSubset(r1 []string, r2 []Checksum) bool {
	for len(r1) > 0 && len(r2) > 0 {
		if r1[0] == r2[0].Kind {
			r1 = r1[1:]
		}
		r2 = r2[1:]
	}

	if len(r1) > 0 {
		return false
	}

	return true
}

// Still working on this...
const dbgCache = false

// maybeMigrate tries to migrate the data from the cache to the node.
func maybeMigrate(cache, res *MTnode, trimPrefix string) {
	if res.IsDir() {
		return
	}

	if res.csums != nil {
		return
	}

	fp := res.Path()

	p := strings.TrimPrefix(fp, trimPrefix)

	oldRes, err := mtreeChdir(cache, p)
	if err != nil {
		if dbgCache {
			fmt.Println("JDBG:", "!migrate", "path", fp, trimPrefix)
		}
		return
	}

	if oldRes.mtimeNsecs != res.mtimeNsecs {
		if dbgCache {
			fmt.Println("JDBG:", "!migrate", "mtime", p)
		}
		return
	}
	if oldRes.size != res.size {
		if dbgCache {
			fmt.Println("JDBG:", "!migrate", "size", p, oldRes.size, res.size)
		}
		return
	}

	if !chksumKindSubset(calcChecksumKinds, oldRes.csums) {
		if dbgCache {
			fmt.Println("JDBG:", "!migrate", "hash", p)
		}
		return
	}
	if dbgCache {
		fmt.Println("JDBG:", "migrate", p)
	}
	res.csums = oldRes.csums
}

// cacheNodes reads the cache information for each node, keeps order the same.
func cacheNodes(nodes <-chan *MTnode, qlen int, cache *MTnode,
	trimPrefix string) <-chan *MTnode {
	if cache == nil {
		return nodes
	}

	cacheNodes := make(chan *MTnode, qlen)

	var wg sync.WaitGroup
	wg.Add(qlen)

	for i := 0; i < qlen; i++ {
		go func() {
			for res := range nodes {
				maybeMigrate(cache, res, trimPrefix)
				cacheNodes <- res
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(cacheNodes)
	}()

	return cacheNodes
}

// progressLenNodes gets all the nodes to get the total number, keeps order the same.
// NOTE: This is sometimes faster and sometimes slower??
func progressLenNodes(nodes <-chan *MTnode, qlen int) (<-chan *MTnode, int64) {
	lenNodes := make(chan *MTnode, qlen)
	lenChan := make(chan int64)

	go func() {
		h := []*MTnode{}
		for n := range nodes {
			h = append(h, n)
		}

		lenChan <- int64(len(h))
		close(lenChan)

		for _, n := range h {
			lenNodes <- n
		}
		close(lenNodes)
	}()

	return lenNodes, <-lenChan
}

// digest gets data for files/symlinks and creates the checksum data for them.
func digest(res *MTnode, dbar *mpb.Bar) {
	if res == nil {
		panic("res is nil")
	}

	if !res.IsDir() {
		res.Checksum("")
	}

	if dbar != nil {
		dbar.Increment()
	}
}

func digestNodes(nodes <-chan *MTnode, qlen int, numNodes int64,
	progress string) <-chan *MTnode {
	digestNodes := make(chan *MTnode, qlen)

	var wg sync.WaitGroup
	wg.Add(qlen)

	var p *mpb.Progress
	var dbar *mpb.Bar
	if progress != "" {
		p = mpb.New(mpb.WithWaitGroup(&wg))
		dbar = p.AddBarDef(numNodes, progress, decor.Unit_k)
	}

	for i := 0; i < qlen; i++ {
		go func() {
			for res := range nodes {
				digest(res, dbar)
				digestNodes <- res
			}
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		if p != nil {
			p.Stop()
		}
		close(digestNodes)
	}()

	return digestNodes
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

type MTConfRemote struct {
	Name string
	URL  string
	User string

	// FIXME: use interface...
	dlType string // http/https or ssh/scp/sftp
	dlSSH  *ssh.Client
	dlSFTP *sftp.Client
}

type MTConf struct {
	Remote    *MTConfRemote
	AutoScrub uint // Auto scrub amount in 0.01% units. 0-10000
	checkSums []string
}

type MTRoot struct {
	Nodes          *MTnode
	Cache          *MTnode
	LatestSnapshot *MTnode

	DotMtreePath string
	RootOffset   string
	Conf         *MTConf
}

// MtreePath Generate data from FS for root path. Also returns last snapshot,
// if available.
func MtreePath(root string, needCachingData, filter,
	progress, needOldSnap bool) (*MTRoot, error) {

	numDigesters := numCPUDigesters()

	root, err := normPath(root)
	if err != nil {
		return nil, err
	}

	rootNode, nodes, errc := walkFiles(root, numDigesters, filter)

	var numNodes int64
	if progress {
		nodes, numNodes = progressLenNodes(nodes, numDigesters)
	}

	retRoot := &MTRoot{}
	hasCache := setupConfig(retRoot, root)

	if hasCache {
		maybeLatestSnapshotCache(retRoot, needOldSnap, progress)
		cache := retRoot.Cache
		osnap := retRoot.LatestSnapshot
		if retRoot.RootOffset != "" {
			if cache != nil {
				cache, err = mtreeChdir(cache, retRoot.RootOffset)
				if err != nil {
					cache = nil
				}
			}
			if osnap != nil {
				osnap, err = mtreeChdir(osnap, retRoot.RootOffset)
				if err != nil {
					osnap = nil
				}
			}
			// FIXME: if off is a file?
		}

		nodes = statNodes(nodes, numDigesters)
		nodes = cacheNodes(nodes, numDigesters, cache, root+"/")
		nodes = cacheNodes(nodes, numDigesters, osnap, root+"/")
	} else if needCachingData {
		nodes = statNodes(nodes, numDigesters)
	}

	progText := ""
	if progress {
		progText = path.Base(root) + " (files): "
	}
	nodes = digestNodes(nodes, numDigesters, numNodes, progText)

	for r := range nodes {
		if r.err != nil {
			fmt.Fprintln(os.Stderr, r.err)
		}
	}

	// Check whether the Walk failed.
	if err := <-errc; err != nil {
		return nil, err
	}

	// Walk to the starting point:
	ret := ensureDir(rootNode, root)

	// Blank the full path out at either:
	if retRoot.LatestSnapshot == nil { // The user supplied path (nearest dir.)
		dir := ret
		if !dir.IsDir() {
			dir = dir.parent
		}
		dir.parent = nil
	} else { // The .mtree root
		if retRoot.RootOffset == "" {
			ret.parent = nil

			// FIXME: could be concurrent ... but need to wait.
			// FIXME: Needs to only write a new file when it changes...
			// FIXME: Cleanup old files.
			// FIXME: Needs to do the merging for non-root cache saves.
			storeWriteDotMtree(root+"/.mtree", "/cache/", false, ret)
		} else {
			parents := len(strings.Split(retRoot.RootOffset, "/"))
			mtree := ret
			for i := 0; i < parents; i++ {
				if mtree.parent == nil {
					panic(fmt.Sprintf("Bad subset: %s = %s",
						retRoot.RootOffset, ret.Path()))
				}
				mtree = mtree.parent
			}
			mtree.parent = nil
		}
	}

	retRoot.Nodes = ret

	return retRoot, nil
}

// MtreePathOrFile Generate data from FS for root path, or from an mtree file
func MtreePathOrFile(root string, needCachingData, filter,
	progress, needOldSnap bool) (*MTRoot, error) {

	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() || !strings.Contains(root, ".mtree") {
		return MtreePath(root, needCachingData, filter, progress, needOldSnap)
	}

	m, e := MtreeFile(root, progress)
	if e != nil {
		return nil, err
	}

	retRoot := &MTRoot{Nodes: m}
	return retRoot, nil
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

func formatFK(f float64) string {
	ext := " "
	switch {
	case f >= TB:
		f /= TB
		ext = "T"
	case f >= GB:
		f /= GB
		ext = "G"
	case f >= MB:
		f /= MB
		ext = "M"
	case f >= KB:
		f /= KB
		ext = "K"
	}
	return fmtSprint(f, ext)
}
func formatK(i int64) string {
	return formatFK(float64(i))
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

func _muinb(ui bool, size int64) string {
	if !ui {
		return fmt.Sprintf("%d", size)
	}
	return formatKB(size)
}

func _muin(ui bool, size int64) string {
	if !ui {
		return fmt.Sprintf("%d", size)
	}
	return formatK(size)
}

func b2s(b []byte) string {
	return fmt.Sprintf("%x", b)
}

func uiChecksum(r *MTnode, ui bool) string {
	chksum := b2s(r.Checksum(calcChecksumKindPrimary))

	if ui {
		uilen := uiChecksumLen
		if uilen > len(chksum) {
			uilen = 0
		}
		if uilen > 0 {
			chksum = chksum[:uiChecksumLen]
		}
	}
	return chksum
}

func uiPath(r *MTnode, tree bool) string {
	if !tree {
		return r.Path()
	}

	var fn string
	depth := r.Depth()
	if depth == 0 {
		fn = r.name
	} else {
		indent := strings.Repeat(" |  ", depth-1) + " \\_ "
		fn = indent + r.name
	}

	return fn
}

func prntListMtree(r *MTnode, tree, ui bool, sizePrefix string) {
	chksum := uiChecksum(r, ui)

	fn := uiPath(r, tree)

	if ui && r.IsDir() && r.parent != nil {
		fn = fn + "/"
	}

	fmt.Printf("%s %s%s %s\n", chksum, sizePrefix, _muinb(ui, r.Size()), fn)
}

func prntDiffMtree(r *MTnode, tree, ui bool, sizePrefix string, osize int64) {
	chksum := uiChecksum(r, ui)

	fn := uiPath(r, tree)

	if ui && r.IsDir() && r.parent != nil {
		fn = fn + "/"
	}

	dsize := " "
	if ui {
		dsize = "     "
	}

	nsize := r.Size()
	if nsize == osize {
		fmt.Printf("%s %s%s  %s%s\n", chksum, sizePrefix, _muinb(ui, nsize),
			dsize, fn)
	} else if nsize >= osize {
		fmt.Printf("%s %s%s+%s %s\n", chksum, sizePrefix, _muinb(ui, nsize),
			_muinb(ui, nsize-osize), fn)
	} else {
		fmt.Printf("%s %s%s-%s %s\n", chksum, sizePrefix, _muinb(ui, nsize),
			_muinb(ui, osize-nsize), fn)
	}
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

// FIXME: This doesn't do any caching, Eg. Num() and LatestModTime()
func prntInfoMtreeIn(node *MTnode, cachingData, ui bool,
	checksumKindMaxLen int) {
	fmt.Println("Name:", node.Path())
	// p := message.NewPrinter(message.MatchLanguage("en"))
	// p.Println("  Num     :", m.Num())
	if node.IsDir() {
		fmt.Println("  Num     :", _muin(ui, int64(node.Num())))
	}
	fmt.Println("  Size    :", _muinb(ui, node.Size()))
	if cachingData {
		timeFmt := time.RFC3339Nano
		if ui { // Similar, but with spaces...
			timeFmt = "2006-01-02 15:04:05.999999999 Z07:00"
		}
		fmt.Println("  Mod Time:", node.LatestModTime().Format(timeFmt))
	}
	for _, csum := range calcChecksumKinds {
		// Cache dir. checksum so it doesn't stop in the middle of the line
		node.Checksum(csum)
		fmt.Printf("    %-*s: %s\n", 4+checksumKindMaxLen, "Chk-"+csum,
			b2s(node.Checksum(csum)))
	}
}

func prntMaxChecsumKindLen() int {
	mlen := 0
	for _, csum := range calcChecksumKinds {
		if len(csum) > mlen {
			mlen = len(csum)
		}
	}
	return mlen
}

func prntInfoMtree(node *MTnode, cachingData, ui bool) {
	prntInfoMtreeIn(node, cachingData, ui, prntMaxChecsumKindLen())
}

func prntInfoMtreedIn(node *MTnode, cachingData, ui bool,
	checksumKindMaxLen int) {
	leafOnly := false
	if !leafOnly || !node.IsDir() || len(node.children) == 0 {
		prntInfoMtreeIn(node, cachingData, ui, checksumKindMaxLen)
	}

	if !node.IsDir() {
		return
	}

	for _, c := range node.Children() {
		prntInfoMtreedIn(c, cachingData, ui, checksumKindMaxLen)
	}
}

func prntInfoMtreed(node *MTnode, cachingData, ui bool) {
	prntInfoMtreedIn(node, cachingData, ui, prntMaxChecsumKindLen())
}

func usageCmdEqual() {
	fmt.Fprintln(os.Stderr, "Usage: mtree check <dir> <check> [check...]")
}
func fullUsageCmdEqual(exitCode int) {
	usageCmdEqual()
	flag.PrintDefaults()
	os.Exit(exitCode)
}
func usageCmdConfig() {
	fmt.Fprintln(os.Stderr, "Usage: mtree config [value] [newvalue...]")
}
func fullUsageCmdConfig(exitCode int) {
	usageCmdConfig()
	flag.PrintDefaults()
	os.Exit(exitCode)
}
func usageCmdDiff() {
	fmt.Fprintln(os.Stderr, "Usage: mtree diff [file/dir] [file/dir]")
}
func fullUsageCmdDiff(exitCode int) {
	usageCmdDiff()
	flag.PrintDefaults()
	os.Exit(exitCode)
}
func usageCmdDef() {
	fmt.Fprintln(os.Stderr, "Usage: mtree <cmd> [args...]")
	fmt.Fprintln(os.Stderr, "             list     [dir]")
	fmt.Fprintln(os.Stderr, "             tree     [dir]")
	fmt.Fprintln(os.Stderr, "             info     [dir]")
	fmt.Fprintln(os.Stderr, "             summary  [dir]")
	fmt.Fprintln(os.Stderr, "             diff     [dir/*.mtree] [dir/*.mtree]")
	fmt.Fprintln(os.Stderr, "             equal    <dir> <checksums>")

	fmt.Fprintln(os.Stderr, "             init     <dir>")
	fmt.Fprintln(os.Stderr, "             snapshot <dir>")
	fmt.Fprintln(os.Stderr, "             config")
	fmt.Fprintln(os.Stderr, "             pull")
	fmt.Fprintln(os.Stderr, "             sync     [dir]")
	fmt.Fprintln(os.Stderr, "             download [dir]")
	fmt.Fprintln(os.Stderr, "             rdiff")
}
func fullUsageCmdDef(exitCode int) {
	usageCmdDef()
	flag.PrintDefaults()
	os.Exit(exitCode)
}

type cmdType int

const (
	cmdUnknown cmdType = iota
	cmdList
	cmdTree
	cmdInfo
	cmdSummary
	cmdEqual
	cmdConfig
	cmdSnapshot
	cmdInitialize
	cmdDifference
	cmdFile
	cmdFileSum
	cmdPull
	cmdSyncMod
	cmdSyncDel
	cmdDownload
	cmdRdiff
)

func parseCmd(cmd []string) (cmdType, []string) {
	switch cmd[0] {
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
		return cmdList, cmd[1:]

	case "directory-tree":
		fallthrough
	case "dir-tree":
		fallthrough
	case "tree":
		return cmdTree, cmd[1:]

	case "directory-information":
		fallthrough
	case "dir-information":
		fallthrough
	case "information":
		fallthrough
	case "directory-info":
		fallthrough
	case "dir-info":
		fallthrough
	case "info":
		return cmdInfo, cmd[1:]

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
		return cmdSummary, cmd[1:]

	case "eq":
		fallthrough
	case "equal":
		fallthrough
	case "chk":
		fallthrough
	case "check":
		return cmdEqual, cmd[1:]

	case "configuration":
		fallthrough
	case "config":
		fallthrough
	case "conf":
		return cmdConfig, cmd[1:]

	case "snapshot":
		fallthrough
	case "snap":
		return cmdSnapshot, cmd[1:]

	case "init":
		return cmdInitialize, cmd[1:]

	case "difference":
		fallthrough
	case "diff":
		if len(cmd) > 1 && cmd[1] == "remote" {
			return cmdRdiff, cmd[2:]

		}
		return cmdDifference, cmd[1:]

	case "file": // FIXME:
		return cmdFile, cmd[1:]
	case "file-sum": // FIXME:
		return cmdFileSum, cmd[1:]

	case "pull":
		return cmdPull, cmd[1:]

	case "sync":
		return cmdSyncMod, cmd[1:]
	case "sync-del":
		fallthrough
	case "sync-delete":
		return cmdSyncDel, cmd[1:]

	case "dl":
		fallthrough
	case "download":
		return cmdDownload, cmd[1:]

	case "rdiff":
		fallthrough
	case "remote-diff":
		fallthrough
	case "remote-difference":
		return cmdRdiff, cmd[1:]

	default:
		return cmdUnknown, nil
	}
}

func mkpathMust(r, p string) {
	dir := r + "/" + p
	if err := os.Mkdir(dir, 0770); err != nil {
		if fi, serr := os.Stat(dir); serr == nil && fi.IsDir() {
			return
		}
		fmt.Fprintf(os.Stderr, "Failed to create %s: %v\n", p, err)
	}
}

func setupConfig(mtr *MTRoot, path string) bool {
	dmt, off := findDotMtree(path)
	if dmt == "" {
		return false
	}
	mtr.DotMtreePath = dmt
	mtr.RootOffset = off

	// Load the config.
	cfg, err := ini.Load(dmt + "/config")
	if err == nil {
		const p string = "remote "

		mtr.Conf = &MTConf{}
		mtr.Conf.AutoScrub = cfg.Section("core").Key("autoscrub").MustUint(0)
		// FIXME: checksums...

		for _, sec := range cfg.Sections() {
			sn := sec.Name()
			if !strings.HasPrefix(sn, p) {
				continue
			}
			if usn, err := strconv.Unquote(sn[len(p):]); err != nil {
				continue
			} else {
				sn = usn
			}

			mtr.Conf.Remote = &MTConfRemote{}
			mtr.Conf.Remote.Name = sn
			if url, e := sec.GetKey("url"); e == nil {
				mtr.Conf.Remote.URL = url.MustString("")
			}
			if url, e := sec.GetKey("user"); e == nil {
				mtr.Conf.Remote.User = url.MustString("")
			}
		}
	}

	return true
}

func maybeLatestSnapshotCache(mtr *MTRoot, needOldSnap, flagProgress bool) {
	dmt := mtr.DotMtreePath

	// FIXME: Don't need to load both, optimize it all away behind functions...
	cm, err := latestCache(dmt)
	if err == nil {
		fname := dmt + "/cache/" + cm
		c, _ := MtreeFile(fname, flagProgress)
		mtr.Cache = c
	}

	snapMtree, err := latestSnapshot(dmt, flagProgress)
	if err == nil {
		fname := dmt + "/local/" + snapMtree
		o, _ := MtreeFile(fname, flagProgress)
		mtr.LatestSnapshot = o
	}
}

func main() {
	if os.Getenv("MTREE_PPROF") != "" {
		f, err := os.Create(os.Getenv("MTREE_PPROF"))
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

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
	flag.BoolVar(&flagFast, "fast", false, "Weird speedups")
	progUsage := "show progress bar"
	flag.BoolVar(&flagProgress, "progress", isTermErr, progUsage)
	flag.BoolVar(&flagProgress, "p", isTermErr, progUsage+" (shorthand)")
	flag.BoolVar(&flagFilter, "filter", true, "filter useless entries")
	flag.IntVar(&uiChecksumLen, "ui-checksum-length",
		uiChecksumLen, "length of UI display checksum")
	pchkDef := strings.Join(calcChecksumsUI(), ",")
	flag.StringVar(&flagPChecksum, "checksums", pchkDef, "what checksums to use")
	flag.IntVar(&numCPUWorkers, "workers",
		numCPUWorkers, "manually set number of checksum workers")
	flag.Parse()

	if flagPChecksum != "" && flagPChecksum != pchkDef {
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

		calcChecksumsReset()
		for _, csum := range strings.FieldsFunc(flagPChecksum, f) {
			calcChecksumsAdd(csum)
		}
		if calcChecksumKindPrimary == "" {
			oneOf := strings.Join(validChecksumKinds, ", ")
			fmt.Fprintf(os.Stderr, "Non-valid checksums flag: %s\n"+
				" Choose from: %s\n", flagPChecksum, oneOf)
			fullUsageCmdDef(1)
		}
		calcChecksumsDone()
	}

	if flag.NArg() < 1 {
		fullUsageCmdConfig(1)
	}

	cmdID, args := parseCmd(flag.Args())

	switch cmdID {
	case cmdList:
		fallthrough
	case cmdTree:
		// FIXME: This breaks caching now ... don't do this if we have .mtree
		// This is a hack, but eh.
		//		calcChecksumKinds = []string{calcChecksumKindPrimary}

	default:
	}

	cachingData := !flagFast

	usageExitCode := 1
	if flagHelp {
		usageExitCode = 0
	}

	switch cmdID {
	case cmdList:
		fallthrough
	case cmdTree:
		fallthrough
	case cmdInfo:
		fallthrough
	case cmdSummary:
		fallthrough
	case cmdDownload:
		fallthrough
	case cmdSyncDel:
		fallthrough
	case cmdSyncMod:
		fallthrough
	case cmdDifference:
		fallthrough
	case cmdRdiff:
		if len(args) < 1 {
			args = []string{"."}
		}
	}

	switch cmdID {
	case cmdConfig:
		if flagHelp {
			fullUsageCmdConfig(usageExitCode)
		}

	case cmdEqual:
		if flagHelp || len(args) < 2 {
			fullUsageCmdEqual(usageExitCode)
		}

		// Overrides --checksums flag, but it's pointless otherwise.
		if flagPChecksum != "" {
			fmt.Fprintln(os.Stderr, "Ignoring --checksum flag.")
		}

		calcChecksumsReset()
		for _, arg := range args[1:] {
			i := strings.Index(arg, ":")
			if i == -1 {
				fmt.Fprintln(os.Stderr,
					"Bad format for checksum (Eg. md5:<md5sum>):", arg)
				usageCmdEqual()
				os.Exit(1)
			}

			chkKind := arg[:i]
			if !validChecksum(chkKind) {
				oneOf := strings.Join(validChecksumKinds, ", ")
				fmt.Fprintf(os.Stderr, "Unknown checksum: %s\n"+
					" Choose one of: %s\n", chkKind, oneOf)
				usageCmdEqual()
				os.Exit(1)
			}
			calcChecksumsAdd(chkKind)
		}
		calcChecksumsDone()

	case cmdRdiff:
		fallthrough
	case cmdDifference:
		if flagHelp || len(args) > 2 {
			fullUsageCmdDiff(usageExitCode)
		}

	case cmdPull:
		if flagHelp {
			fullUsageCmdDef(usageExitCode)
		}

	default:
		if flagHelp || len(args) != 1 {
			fullUsageCmdDef(usageExitCode)
		}
	}

	// Create an mtree, or two
	var mtr *MTRoot
	var omtree *MTnode
	needOldSnap := false
	switch cmdID {
	case cmdConfig:
		mtr = &MTRoot{}
		dot, err := normPath(".")
		if err == nil {
			setupConfig(mtr, dot)
		}

	case cmdSnapshot:
		cachingData = true
		needOldSnap = true
		fallthrough
	case cmdList:
		fallthrough
	case cmdTree:
		fallthrough
	case cmdInfo:
		fallthrough
	case cmdSummary:
		fallthrough
	case cmdDownload:
		fallthrough
	case cmdSyncDel:
		fallthrough
	case cmdSyncMod:
		fallthrough
	case cmdEqual:
		m, err := MtreePath(args[0], cachingData, flagFilter,
			flagProgress, needOldSnap)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		mtr = m

	case cmdFile:
		fallthrough
	case cmdFileSum:
		m, err := MtreeFile(args[0], flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		mtr = &MTRoot{Nodes: m}
		if cmdID == cmdFile {
			cmdID = cmdInfo
		} else {
			cmdID = cmdSummary
		}

	case cmdRdiff:
		// FIXME: local vs. upstream
		dmt, off := findDotMtree(args[0])
		omtreeName, err := latestSnapshot(dmt, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		omtreeName = off + ".mtree/local/" + omtreeName

		mtr = &MTRoot{}
		dot, err := normPath(".")
		if err == nil {
			setupConfig(mtr, dot)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't find .mtree/config.")
			os.Exit(2)
		}
		if mtr == nil || mtr.Conf == nil || mtr.Conf.Remote == nil {
			fmt.Fprintln(os.Stderr, "No .mtree/config.")
			os.Exit(2)
		}
		if mtr.RootOffset != "" { // FIXME
			fmt.Fprintln(os.Stderr, "Atm. need to be in the root of the .mtree.")
			os.Exit(1)
		}

		rpath := ".mtree/remote/" + mtr.Conf.Remote.Name

		fname, err := latestSnapshot(rpath, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, "remote HEAD:", err)
			os.Exit(1)
		}

		rmtreeName := rpath + "/" + fname
		args = []string{rmtreeName, omtreeName}
		fallthrough

	case cmdDifference:
		// FIXME: If dirs.
		// diff = current vs. last snap
		// diff x = current x vs. last snap
		// diff dirx filey / filex diry = load snap from file and diff.

		m, err := MtreePathOrFile(args[0],
			cachingData, flagFilter, flagProgress, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		mtr = m

		if len(args) <= 1 {
			dmt, off := findDotMtree(args[0])
			if dmt == "" {
				fmt.Fprintln(os.Stderr, "Can't find .mtree from:", args[0])
				os.Exit(1)
			}
			omtree = mtr.LatestSnapshot
			if omtree == nil { // This should fail, or we'd get it from the cache
				omtreeName, err := latestSnapshot(dmt, flagProgress)
				if err == nil {
					omtree, err = MtreeFile(dmt+"/"+omtreeName, flagProgress)
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "Can't load snapshot from:",
						dmt, err)
					os.Exit(1)
				}
				if off != "" {
					omtree, err = mtreeChdir(omtree, off)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Can't find old off:",
							"from:", omtree.Path(), err)
						os.Exit(1)
					}
				}
			}
			break
		}
		omtree = mtr.Nodes

		mtr, err = MtreePathOrFile(args[1],
			cachingData, flagFilter, flagProgress, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}

	case cmdPull:
		mtr = &MTRoot{}
		dot, err := normPath(".")
		if err == nil {
			setupConfig(mtr, dot)
		}

	}

	var mtree *MTnode
	if mtr != nil {
		mtree = mtr.Nodes
	}

	switch cmdID {
	case cmdList:
		prntListMtreed(mtree, false, flagUI, "")
	case cmdTree:
		prntListMtreed(mtree, true, flagUI, "")

	case cmdInfo:
		prntInfoMtreed(mtree, cachingData, flagUI)

	case cmdSummary:
		prntInfoMtree(mtree, cachingData, flagUI)

	case cmdEqual:
		chkArgs := args[1:]
		chkDone := make([]bool, len(chkArgs))
		failedChecksum := false
		for _, csum := range calcChecksumKinds {
			for i, arg := range chkArgs {
				if len(arg) < (len(csum) + 2) {
					continue
				}
				if !strings.HasPrefix(arg, csum+":") {
					continue
				}

				argCsum := arg[len(csum)+1:]
				fndCsum := b2s(mtree.Checksum(csum))
				if !strings.HasPrefix(fndCsum, argCsum) {
					fmt.Fprintln(os.Stderr, "Failed checksum:", csum, arg)
					failedChecksum = true
				}
				chkDone[i] = true
			}
		}

		if failedChecksum {
			os.Exit(4)
		}

		for i, chk := range chkDone {
			if chk {
				continue
			}

			fmt.Fprintln(os.Stderr, "No match for checksum:", chkArgs[i])
			os.Exit(4)
		}

	case cmdConfig:
		// https://ini.unknwon.io/docs/intro/getting_started
		usr, err := user.Current()
		if err != nil {
			fmt.Fprintln(os.Stderr, "user:", err)
			os.Exit(1)
		}
		// FIXME: Use XDG_CONFIG_HOME?
		path := fmt.Sprintf("%s/.config/mtree/config", usr.HomeDir)
		cfg, err := ini.Load(path)
		if err != nil {
			fmt.Printf("Fail to read config file: %v", err)
		} else {
			fmt.Println("[core]")
			for _, key := range []string{"progress", "ui", "ui-checksum-length",
				"checksums"} {
				fmt.Println(key, "=", cfg.Section("core").Key(key))
			}

			fmt.Println("[alias]")
			for _, key := range cfg.Section("alias").KeyStrings() {
				fmt.Println(key, "=", cfg.Section("alias").Key(key))
			}
		}

		if mtr != nil && mtr.Conf != nil {
			fmt.Println("== \"" + mtr.RootOffset + ".mtree/config\" ==")
			fmt.Println("[core]")
			fmt.Println("autocrub = ", mtr.Conf.AutoScrub)
			if mtr.Conf.Remote != nil {
				fmt.Printf("[remote %s]\n", strconv.Quote(mtr.Conf.Remote.Name))
				fmt.Printf("url  = %s\n", mtr.Conf.Remote.URL)
				fmt.Printf("user = %s\n", mtr.Conf.Remote.User)
			}
		}

	case cmdSnapshot:
		dmt, _ := findDotMtree(args[0])
		if dmt == "" {
			fmt.Fprintln(os.Stderr, "Can't find .mtree from:", args[0])
			os.Exit(1)
		}

		// Make sure the dir. checksums are valid.
		for _, csum := range calcChecksumKinds {
			mtree.Checksum(csum)
		}

		if omtree != nil && cmpChksumEq(omtree, mtree) {
			fmt.Println("Nothing changed:")
			// prntListMtree(mtree, false, flagUI, "")
			prntInfoMtree(mtree, cachingData, flagUI)
			break
		}

		if omtree == nil || omtree.parent == nil {
			// Simple case, no old snapshot
			for mtree.parent != nil {
				// Going to the root of the snapshot ...
				mtree = mtree.parent
			}
		} else {
			// Need to merge the new snapshot data into the old snapshot
			omtree = omtree.parent
			omtree.Replace(mtree)

			mtree = omtree
			for mtree.parent != nil {
				// Going to the root of the snapshot ...
				mtree = mtree.parent
			}
		}

		bfn, err := storeWriteDotMtree(dmt, "/local/", true, mtree)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't write snap:", err)
			os.Exit(1)
		}
		nfn := dmt + "/local/" + bfn + ".mtree"

		// Now we write the mtree of the latest mtree ... :-o
		rootx2 := rootRes()
		mtreex2l := ensureDir(rootx2, path.Dir(nfn))
		mtreex2 := mtreex2l.parent
		mtreex2ll := newRes(mtreex2l, bfn+".mtree", 0)

		if fi, err := os.Lstat(nfn); err == nil {
			mtreex2ll.mtimeNsecs = fi.ModTime().UnixNano()
		}

		checksumFile(mtreex2ll, "")
		mtreex2.parent = nil

		fox2, err := roc.Create(dmt + "/HEAD")
		if err != nil {
			fmt.Fprintln(os.Stderr, "snap:", err)
			os.Exit(1)
		}
		defer fox2.Close()

		iow := bufio.NewWriter(fox2)

		storeWriteFile(iow, mtreex2ll)
		if err := iow.Flush(); err != nil {
			fmt.Fprintln(os.Stderr, "Can't write HEAD:", err)
			os.Exit(1)
		}

		os.Rename(dmt+"/HEAD", dmt+"/PREV") // Ignore errors

		if err := fox2.CloseRename(); err != nil {
			fmt.Fprintln(os.Stderr, "Can't write HEAD:", err)
			os.Exit(1)
		}

		prntInfoMtree(mtree, cachingData, flagUI)

	case cmdInitialize:
		mkpathMust(args[0], ".mtree")
		mkpathMust(args[0], ".mtree/local")
		mkpathMust(args[0], ".mtree/remote")
		mkpathMust(args[0], ".mtree/cache")
		mkpathMust(args[0], ".mtree/data")
		// FIXME: Dump config to .mtree/config

	case cmdRdiff:
		fallthrough
	case cmdDifference:
		// Make sure the dir. checksums are valid.
		for _, csum := range calcChecksumKinds {
			mtree.Checksum(csum)
		}

		prntDiff(omtree, mtree, false, flagUI)

	case cmdPull:
		if mtr == nil || mtr.Conf == nil || mtr.Conf.Remote == nil {
			fmt.Fprintln(os.Stderr, "No .mtree/config.")
			os.Exit(1)
		}

		if mtr.RootOffset != "" { // FIXME
			fmt.Fprintln(os.Stderr, "Atm. need to be in the root of the .mtree.")
			os.Exit(1)
		}

		fmt.Printf("pulling %s\n", strconv.Quote(mtr.Conf.Remote.Name))

		dlpath := ".mtree/remote/" + mtr.Conf.Remote.Name
		mkpathMust(path.Dir(mtr.DotMtreePath), dlpath)

		if err := dlSetup(mtr, flagProgress); err != nil {
			fmt.Fprintln(os.Stderr, "pull:", err)
			os.Exit(1)
		}
		defer dlClose(mtr)

		fmt.Printf("  dl HEAD\n")
		if err := dlFile(mtr, dlpath, ".mtree/HEAD"); err != nil {
			fmt.Fprintln(os.Stderr, "remote HEAD:", err)
			os.Exit(1)
		}

		fname, err := latestSnapshot(dlpath, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, "remote HEAD:", err)
			os.Exit(1)
		}

		if false {
			// FIXME: Need to check the checksums ... sigh

		}
		fmt.Printf("  dl %s\n", fname)

		if err := dlFile(mtr, dlpath, ".mtree/local/"+fname); err != nil {
			fmt.Fprintln(os.Stderr, "remote mtree:", err)
			os.Exit(1)
		}

	case cmdDownload: // Download missing files
		fallthrough
	case cmdSyncDel: // Download missing/changed files, and delete others
		fallthrough
	case cmdSyncMod: // Download missing/changed files
		if mtr == nil || mtr.Conf == nil || mtr.Conf.Remote == nil {
			fmt.Fprintln(os.Stderr, "No .mtree/config.")
			os.Exit(1)
		}

		if mtr.RootOffset != "" { // FIXME
			fmt.Fprintln(os.Stderr, "Atm. need to be in the root of the .mtree.")
			os.Exit(1)
		}

		dlpath := ".mtree/remote/" + mtr.Conf.Remote.Name

		fname, err := latestSnapshot(dlpath, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, "remote HEAD:", err)
			os.Exit(1)
		}
		fname = dlpath + "/" + path.Base(fname)

		m, err := MtreeFile(fname, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Remote .mtree:", err)
			os.Exit(2)
		}

		if err := dlSetup(mtr, flagProgress); err != nil {
			fmt.Fprintln(os.Stderr, "pull:", err)
			os.Exit(1)
		}
		defer dlClose(mtr)

		// Note that old is remote, and new is local ... this means:
		//  Delete's need to be downloaded
		//  Additions need to be deleted (maybe)
		cbDiff(m, mtree, func(n *MTnode, cbT cbType, on ...*MTnode) {

			switch cbT {
			case cbEqual:
				return

			case cbAdd:
				if cmdID != cmdSyncDel {
					return
				}

				os.RemoveAll(n.Path())

			case cbMod:
				if n.IsDir() {
					return
				}

				if cmdID == cmdDownload {
					return
				}
				fallthrough
			case cbDel:
				if n.IsDir() {
					mkpathMust(n.Path(), "")
					return
				}

				rpath := n.Path()
				fdir := strings.IndexByte(rpath, '/')
				rpath = rpath[fdir+1:]
				lpath := path.Dir(rpath)

				fmt.Printf("  dl %s\n", rpath)
				if err := dlFile(mtr, lpath, rpath); err != nil {
					fmt.Fprintln(os.Stderr, "remote mtree:", err)
					os.Exit(1)
				}
			}
		})

	default:
		usageCmdDef()
		os.Exit(1)
	}
}

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
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

	"golang.org/x/crypto/ssh/terminal"

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
func fcmpLess(a, b string) bool {
	if fcmp(a, b) < 0 {
		return true
	}
	return false
}

// Children gives you the sorted children of this node.
func (r *MTnode) Children() []*MTnode {
	if !r.sorted {
		children := r.ChildrenUnsorted()
		sort.Slice(children, func(i, j int) bool {
			return fcmpLess(children[i].name, children[j].name)
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
		checksumSymlink(r, kind)
		return r.Checksum(kind)
	} else if !r.IsDir() {
		checksumFile(r, kind)
		if r.err != nil {
			c := data2csum(kind, []byte{})
			return c
		}
		return r.Checksum(kind)
	}

	// Is a directory...
	// merge all the data from all the children...

	// For large sets this can be slow, so parallel ftw.
	r.childrenSetupChecksums(kind, 0)

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

func newRes(dres *MTnode, base string, mode os.FileMode) *MTnode {
	res := &MTnode{name: base, parent: dres,
		isDir: mode.IsDir(), isSymlink: mode&os.ModeSymlink != 0}
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
	needCachingData, filter, progress bool) (<-chan *MTnode, int64, <-chan error) {

	nodes := make(chan *MTnode, qlen)
	errc := make(chan error, 1)
	go func() {
		// Close the channel after Walk returns.
		defer close(nodes)

		rootFI, err := os.Stat(wroot)
		if err != nil {
			errc <- err
			return
		}

		root := rootRes()

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
		errc <- godirwalk.Walk(wroot, &godirwalk.Options{
			Unsorted: true, // faster, yet non-deterministic enumeration
			Callback: func(p string, de *godirwalk.Dirent) error {
				mode := de
				name := de.Name()

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

				nodes <- res
				//				select {
				//				case nodes <- res:
				//				case <-done:
				//					return errors.New("walk canceled")
				//				}
				return nil
			},
			ErrorCallback: func(p string, e error) godirwalk.ErrorAction {
				ensureParentDir(root, p, pparent, ppent)
				fmt.Fprintln(os.Stderr, e)
				return godirwalk.SkipNode
			},
			//  We can't do this because we don't know when the checksum workers
			// will be finished with the child nodes.
			//			PostChildrenCallback: func(p string, de *godirwalk.Dirent) error {
			//				res := ensureDir(root, p)
			//				res.dirDone()
			//			},
		})
		nodes <- root
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

// digestWorker walks a work queue and calls digest()
func digestWorker(done chan<- *MTnode, paths <-chan *MTnode, dbar *mpb.Bar) {
	for res := range paths {
		digest(res, dbar)
		done <- res
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

// MtreePath Generate data from FS for root path
func MtreePath(root string, needCachingData, filter, progress bool) (*MTnode, error) {

	numDigesters := numCPUDigesters()

	root, err := normPath(root)
	if err != nil {
		return nil, err
	}

	nodes, nnodes, errc := walkFiles(root, numDigesters,
		needCachingData, filter, progress)

	done := make(chan *MTnode)

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
			digestWorker(done, nodes, dbar)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		if p != nil {
			p.Stop()
		}
		close(done)
	}()

	var ret *MTnode
	for r := range done {
		if r.err != nil {
			fmt.Fprintln(os.Stderr, r.err)
		}
		if r.name == "/" {
			ret = r
		}
	}

	// Check whether the Walk failed.
	if err := <-errc; err != nil { // HLerrc
		return nil, err
	}

	// Walk to the starting point:
	ret = ensureDir(ret, root)
	//	ret = first(ret) // Skip the usuless root nodes

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

// FIXME: This doesn't do any caching, Eg. Size()
func prntListMtree(r *MTnode, tree, ui bool, sizePrefix string) {
	chksum := b2s(r.Checksum(calcChecksumKindPrimary))
	if ui {
		uilen := uiChecksumLen
		if uilen < len(chksum) {
			uilen = 0
		}
		if uilen > 0 {
			chksum = chksum[:uiChecksumLen]
		}
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

	fmt.Printf("%s %s%s %s\n", chksum, sizePrefix, _muinb(ui, r.Size()), fn)
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
func usageCmdDef() {
	fmt.Fprintln(os.Stderr, "Usage: mtree config|equal|list|summary|tree <dir> [check...]")
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
)

func parseCmd(cmd string) cmdType {
	switch cmd {
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
		return cmdList

	case "directory-tree":
		fallthrough
	case "dir-tree":
		fallthrough
	case "tree":
		return cmdTree

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
		return cmdInfo

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
		return cmdSummary

	case "eq":
		fallthrough
	case "equal":
		fallthrough
	case "chk":
		fallthrough
	case "check":
		return cmdEqual

	case "configuration":
		fallthrough
	case "config":
		fallthrough
	case "conf":
		return cmdConfig

	default:
		return cmdUnknown
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
		uiChecksumLen, "manually set number of checksum workers")
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
			oneOf := strings.Join(validChecksumKinds[:], ", ")
			fmt.Fprintf(os.Stderr, "Non-valid checksums flag: %s\n"+
				" Choose from: %s\n", flagPChecksum, oneOf)
			fullUsageCmdDef(1)
		}
		calcChecksumsDone()
	}

	cmdID := parseCmd(flag.Arg(0))

	switch cmdID {
	case cmdList:
		fallthrough
	case cmdTree:
		// This is a hack, but eh.
		calcChecksumKinds = []string{calcChecksumKindPrimary}

	default:
	}

	// FIXME: Using flagFast is a massive hack here. Add caching first ;)
	cachingData := !flagFast

	usageExitCode := 1
	if flagHelp {
		usageExitCode = 0
	}

	switch cmdID {
	case cmdConfig:
		if flagHelp || len(flag.Args()) < 1 {
			fullUsageCmdConfig(usageExitCode)
		}

	case cmdEqual:
		if flagHelp || len(flag.Args()) < 3 {
			fullUsageCmdEqual(usageExitCode)
		}

		// Overrides --checksums flag, but it's pointless otherwise.
		if flagPChecksum != "" {
			fmt.Fprintln(os.Stderr, "Ignoring --checksum flag.")
		}

		calcChecksumsReset()
		for _, arg := range flag.Args()[2:] {
			i := strings.Index(arg, ":")
			if i == -1 {
				fmt.Fprintln(os.Stderr,
					"Bad format for checksum (Eg. md5:<md5sum>):", arg)
				usageCmdEqual()
				os.Exit(1)
			}

			chkKind := arg[:i]
			if !validChecksum(chkKind) {
				oneOf := strings.Join(validChecksumKinds[:], ", ")
				fmt.Fprintf(os.Stderr, "Unknown checksum: %s\n"+
					" Choose one of: %s\n", chkKind, oneOf)
				usageCmdEqual()
				os.Exit(1)
			}
			calcChecksumsAdd(chkKind)
		}
		calcChecksumsDone()

	default:
		if flagHelp || len(flag.Args()) != 2 {
			fullUsageCmdDef(usageExitCode)
		}
	}

	// Create an mtree
	var mtree *MTnode
	switch cmdID {
	case cmdList:
		fallthrough
	case cmdTree:
		fallthrough
	case cmdInfo:
		fallthrough
	case cmdSummary:
		fallthrough
	case cmdEqual:
		m, err := MtreePath(flag.Arg(1), cachingData, flagFilter, flagProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		mtree = m
	}

	switch cmdID {
	case cmdList:
		p := mtree.parent
		mtree.parent = nil
		prntListMtreed(mtree, false, flagUI, "")
		mtree.parent = p
	case cmdTree:
		p := mtree.parent
		mtree.parent = nil
		prntListMtreed(mtree, true, flagUI, "")
		mtree.parent = p

	case cmdInfo:
		p := mtree.parent
		mtree.parent = nil
		prntInfoMtreed(mtree, cachingData, flagUI)
		mtree.parent = p

	case cmdSummary:
		p := mtree.parent
		mtree.parent = nil
		prntInfoMtree(mtree, cachingData, flagUI)
		mtree.parent = p

	case cmdEqual:
		chkArgs := flag.Args()[2:]
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
			fmt.Printf("Fail to read file: %v", err)
			os.Exit(1)
		}

		fmt.Println("[core]")
		for _, key := range []string{"progress", "ui", "ui-checksum-length",
			"checksums"} {
			fmt.Println(key, "=", cfg.Section("core").Key(key))
		}

		fmt.Println("[alias]")
		for _, key := range cfg.Section("alias").KeyStrings() {
			fmt.Println(key, "=", cfg.Section("alias").Key(key))
		}

	default:
		usageCmdDef()
		os.Exit(1)
	}
}

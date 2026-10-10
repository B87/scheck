package github

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // Required Git format checksum, never a persisted secret hash.
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

const mirrorObjectMax = 8 << 20

// Structural hashes remain transient (docs/spec/github-collector.md,
// "Supported objects and traversal").
func gitHash(kind string, b []byte) []byte {
	h := sha1.New() //nolint:gosec // Git object format requires SHA-1, not a security primitive.
	_, _ = io.WriteString(h, kind+" "+strconv.Itoa(len(b))+"\x00")
	_, _ = h.Write(b)
	return h.Sum(nil)
}
func structuralHash(b []byte) []byte { h := sha1.Sum(b); return h[:] } //nolint:gosec // Git format checksum.
type mirrorPack struct {
	name    string
	size    int64
	ids     []string
	offsets []int64
	crc     []uint32
	ends    map[int64]int64
}
type mirrorObject struct {
	kind    string
	data    []byte
	release func()
}

// Fixed-capacity inflation avoids ReadAll growth retaining two backing buffers.
func inflatedBytes(r io.Reader, limit int) ([]byte, error) {
	b := make([]byte, limit)
	n, err := io.ReadFull(r, b)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}
	return b[:n], err
}

func (s *mirrorScan) reserve(n int64) (func(), error) {
	if n < 0 || s.resident+n > 128<<20 {
		return nil, gate.ErrMirrorLimit
	}
	s.resident += n
	return func() { s.resident -= n }, nil
}
func (s *mirrorScan) list(name string) ([]os.DirEntry, func(), error) {
	if err := s.check(); err != nil {
		return nil, nil, err
	}
	// Reserve before ReadDir allocates name-bearing entries. The extra entry
	// detects a cap; retained parent lists keep their charge during recursion.
	remaining := 250000 - s.entries
	budgetEntries := int(((128<<20)-s.resident)/1024) - 1
	remaining = min(remaining, budgetEntries)
	if remaining < 1 {
		return nil, nil, gate.ErrMirrorLimit
	}
	release, err := s.reserve(int64(remaining+1) * 1024)
	if err != nil {
		return nil, nil, err
	}
	items, err := s.files.List(name, remaining)
	release()
	if err != nil {
		return nil, nil, err
	}
	s.entries += len(items)
	release, err = s.reserve(int64(len(items)) * 1024)
	if err != nil {
		return nil, nil, err
	}
	return items, release, nil
}

func (s *mirrorScan) packs() error {
	items, listRelease, err := s.list("objects/pack")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer listRelease()
	slices.SortFunc(items, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var bytesTotal int64
	for _, item := range items {
		if strings.HasSuffix(item.Name(), ".promisor") {
			s.gap("promisor_objects_unassessed")
		}
		if !strings.HasSuffix(item.Name(), ".pack") {
			continue
		}
		if len(s.packFiles) >= 64 {
			return gate.ErrMirrorLimit
		}
		if !strings.HasPrefix(item.Name(), "pack-") || !fullSHA.MatchString(strings.TrimSuffix(strings.TrimPrefix(item.Name(), "pack-"), ".pack")) {
			return errMirrorFormat
		}
		name := path.Join("objects/pack", item.Name())
		f, err := s.files.Open(name, 256<<20)
		if err != nil {
			return err
		}
		st, e := f.Stat()
		if e != nil {
			_ = f.Close()
			return errMirrorCorrupt
		}
		size := st.Size()
		bytesTotal += size
		if bytesTotal > 512<<20 {
			_ = f.Close()
			return gate.ErrMirrorLimit
		}
		if size < 32 {
			_ = f.Close()
			return errMirrorCorrupt
		}
		h := sha1.New() //nolint:gosec // Git format checksum, not stored.
		buf := make([]byte, 64<<10)
		var consumed int64
		for consumed < size-20 {
			if e = s.check(); e != nil {
				_ = f.Close()
				return e
			}
			n, readErr := f.Read(buf[:min(int64(len(buf)), size-20-consumed)])
			if n > 0 {
				_, _ = h.Write(buf[:n])
				consumed += int64(n)
			}
			if readErr != nil || n == 0 {
				_ = f.Close()
				return errMirrorCorrupt
			}
		}
		trailer := make([]byte, 20)
		_, e = io.ReadFull(f, trailer)
		if e != nil || !bytes.Equal(h.Sum(nil), trailer) {
			_ = f.Close()
			return errMirrorCorrupt
		}
		if hex.EncodeToString(trailer) != strings.TrimSuffix(strings.TrimPrefix(item.Name(), "pack-"), ".pack") {
			_ = f.Close()
			return errMirrorCorrupt
		}
		header := make([]byte, 12)
		_, e = f.ReadAt(header, 0)
		_ = f.Close()
		if e != nil || string(header[:4]) != "PACK" || binary.BigEndian.Uint32(header[4:8]) != 2 {
			return errMirrorFormat
		}
		// Reserve the bounded input before ReadAll can allocate it. The subsequent
		// conservative charge includes raw bytes, slice capacity, decoded strings,
		// offsets and both resident and transient index maps.
		inputRelease, err := s.reserve(32 << 20)
		if err != nil {
			return err
		}
		idx, err := s.files.Read(strings.TrimSuffix(name, ".pack")+".idx", 16<<20)
		inputRelease()
		if err != nil {
			return err
		}
		release, err := s.reserve(int64(len(idx)) * 12)
		if err != nil {
			return err
		}
		p, e := parsePackIndex(idx, name, size, trailer, binary.BigEndian.Uint32(header[8:12]))
		if e != nil {
			release()
			return e
		}
		// Account for resident decoded index maps/strings as well as the input.
		s.indexReleases = append(s.indexReleases, release)
		s.packFiles = append(s.packFiles, p)
		s.indexed += len(p.ids)
		if s.indexed > 200000 {
			return gate.ErrMirrorLimit
		}
	}
	return nil
}
func parsePackIndex(b []byte, name string, size int64, trailer []byte, count uint32) (mirrorPack, error) {
	p := mirrorPack{name: name, size: size, ends: map[int64]int64{}}
	if len(b) < 8+1024+40 || !bytes.Equal(b[:4], []byte{255, 't', 'O', 'c'}) || binary.BigEndian.Uint32(b[4:8]) != 2 {
		return p, errMirrorFormat
	}
	if !bytes.Equal(structuralHash(b[:len(b)-20]), b[len(b)-20:]) || !bytes.Equal(b[len(b)-40:len(b)-20], trailer) {
		return p, errMirrorCorrupt
	}
	n := int(binary.BigEndian.Uint32(b[1028:1032]))
	if n > 200000 {
		return p, gate.ErrMirrorLimit
	}
	if uint32(n) != count || len(b) < 1032+n*28+40 {
		return p, errMirrorCorrupt
	}
	large := (len(b) - 1032 - n*28 - 40) / 8
	if 1032+n*28+large*8+40 != len(b) {
		return p, errMirrorCorrupt
	}
	if large > n {
		return p, errMirrorCorrupt
	}
	usedLarge := map[int]bool{}
	prev := uint32(0)
	for i := range 256 {
		v := binary.BigEndian.Uint32(b[8+i*4:])
		if v < prev || v > uint32(n) {
			return p, errMirrorCorrupt
		}
		prev = v
	}
	counts := [256]uint32{}
	seenOffsets := map[int64]bool{}
	for i := range n {
		raw := b[1032+i*20 : 1032+(i+1)*20]
		id := hex.EncodeToString(raw)
		if i > 0 && id <= p.ids[i-1] {
			return p, errMirrorCorrupt
		}
		counts[raw[0]]++
		p.ids = append(p.ids, id)
		p.crc = append(p.crc, binary.BigEndian.Uint32(b[1032+n*20+i*4:]))
		v := binary.BigEndian.Uint32(b[1032+n*24+i*4:])
		off := int64(v)
		if v&0x80000000 != 0 {
			j := int(v & 0x7fffffff)
			if j >= large || usedLarge[j] {
				return p, errMirrorCorrupt
			}
			usedLarge[j] = true
			u := binary.BigEndian.Uint64(b[1032+n*28+j*8:])
			if u > uint64(size) { //nolint:gosec // size is a validated positive pack size, at most 256 MiB.
				return p, errMirrorCorrupt
			}
			off = int64(u) //nolint:gosec // u was bounded by the 256 MiB pack size.
		}
		if off < 12 || off >= size-20 || seenOffsets[off] {
			return p, errMirrorCorrupt
		}
		seenOffsets[off] = true
		p.offsets = append(p.offsets, off)
	}
	if len(usedLarge) != large {
		return p, errMirrorCorrupt
	}
	accumulated := uint32(0)
	for i, v := range counts {
		accumulated += v
		if accumulated != binary.BigEndian.Uint32(b[8+i*4:]) {
			return p, errMirrorCorrupt
		}
	}
	offsets := slices.Clone(p.offsets)
	slices.Sort(offsets)
	if n > 0 && offsets[0] != 12 {
		return p, errMirrorCorrupt
	}
	if n == 0 && size != 32 {
		return p, errMirrorCorrupt
	}
	for i, off := range offsets {
		end := size - 20
		if i+1 < len(offsets) {
			end = offsets[i+1]
		}
		p.ends[off] = end
	}
	return p, nil
}
func (s *mirrorScan) object(id string, depth int, active map[string]bool) (mirrorObject, error) {
	empty := mirrorObject{}
	id = strings.ToLower(id)
	if err := s.check(); err != nil {
		return empty, err
	}
	if depth > 64 {
		return empty, gate.ErrMirrorLimit
	}
	if !fullSHA.MatchString(id) || active[id] {
		return empty, errMirrorCorrupt
	}
	active[id] = true
	defer delete(active, id)
	s.objects++
	if s.objects > 200000 {
		return empty, gate.ErrMirrorLimit
	}
	for _, p := range s.packFiles {
		if i, found := slices.BinarySearch(p.ids, id); found {
			return s.packed(p, i, id, depth, active)
		}
	}
	f, err := s.files.Open("objects/"+id[:2]+"/"+id[2:], 16<<20)
	if err != nil {
		return empty, err
	}
	defer func() { _ = f.Close() }()
	release, err := s.reserve(32 << 20)
	if err != nil {
		return empty, err
	}
	stat, err := f.Stat()
	if err != nil {
		release()
		return empty, errMirrorCorrupt
	}
	br := newPackBytes(f)
	zr, err := zlib.NewReader(br)
	if err != nil {
		release()
		return empty, errMirrorCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(zr, mirrorObjectMax+129))
	closeErr := zr.Close()
	// A bounded read may stop before the compressed stream ends. Report the
	// observed expansion cap before testing complete-stream integrity.
	if len(raw) > mirrorObjectMax+128 {
		release()
		return empty, gate.ErrMirrorLimit
	}
	if err != nil || closeErr != nil || br.n != stat.Size() {
		release()
		return empty, errMirrorCorrupt
	}
	release()
	release, err = s.reserve(int64(cap(raw)) * 2)
	if err != nil {
		return empty, err
	}
	header, data, ok := bytes.Cut(raw, []byte{0})
	kind, length, has := strings.Cut(string(header), " ")
	n, e := parseSize(length)
	if len(data) > mirrorObjectMax {
		release()
		return empty, gate.ErrMirrorLimit
	}
	if !ok || !has || e != nil || len(data) != n || !slices.Contains([]string{"commit", "tree", "blob", "tag"}, kind) || objectID(data, kind) != id {
		release()
		return empty, errMirrorCorrupt
	}
	s.expanded += int64(len(raw))
	if s.expanded > 512<<20 {
		release()
		return empty, gate.ErrMirrorLimit
	}
	return mirrorObject{kind, data, release}, nil
}
func (s *mirrorScan) packed(p mirrorPack, i int, id string, depth int, active map[string]bool) (mirrorObject, error) {
	empty := mirrorObject{}
	f, err := s.files.Open(p.name, 256<<20)
	if err != nil {
		return empty, err
	}
	defer func() { _ = f.Close() }()
	start, end := p.offsets[i], p.ends[p.offsets[i]]
	r := io.NewSectionReader(f, start, end-start)
	crc := crc32.NewIEEE()
	br := newPackBytes(io.TeeReader(r, crc))
	b, e := br.ReadByte()
	if e != nil {
		return empty, errMirrorCorrupt
	}
	typ := int((b >> 4) & 7)
	size := uint64(b & 15)
	shift := uint(4)
	for b&128 != 0 {
		if shift > 60 {
			return empty, errMirrorCorrupt
		}
		b, e = br.ReadByte()
		if e != nil {
			return empty, errMirrorCorrupt
		}
		size |= uint64(b&127) << shift
		shift += 7
	}
	if size > mirrorObjectMax {
		return empty, gate.ErrMirrorLimit
	}
	baseID := ""
	switch typ {
	case 6:
		b, e = br.ReadByte()
		if e != nil {
			return empty, errMirrorCorrupt
		}
		distance := uint64(b & 127)
		for b&128 != 0 {
			if distance > uint64(start)>>7 { //nolint:gosec // start is a validated positive offset below 256 MiB.
				return empty, errMirrorCorrupt
			}
			b, e = br.ReadByte()
			if e != nil {
				return empty, errMirrorCorrupt
			}
			distance = ((distance + 1) << 7) | uint64(b&127)
		}
		if distance == 0 || distance > uint64(start-12) { //nolint:gosec // start >= 12 was validated by the index reader.
			return empty, errMirrorCorrupt
		}
		off := start - int64(distance)
		j := slices.Index(p.offsets, off)
		if j < 0 {
			return empty, errMirrorCorrupt
		}
		baseID = p.ids[j]
	case 7:
		raw := make([]byte, 20)
		if _, e = io.ReadFull(br, raw); e != nil {
			return empty, errMirrorCorrupt
		}
		baseID = hex.EncodeToString(raw)
	}
	release, err := s.reserve(int64(size)*2 + 64)
	if err != nil {
		return empty, err
	}
	zr, err := zlib.NewReader(br)
	if err != nil {
		release()
		return empty, errMirrorCorrupt
	}
	data, err := inflatedBytes(zr, int(size)+1) //nolint:gosec // size was bounded to mirrorObjectMax before allocation.
	closeErr := zr.Close()
	if err != nil || closeErr != nil || uint64(len(data)) != size || br.n != end-start || crc.Sum32() != p.crc[i] {
		release()
		return empty, errMirrorCorrupt
	}
	s.expanded += int64(len(data))
	if s.expanded > 512<<20 {
		release()
		return empty, gate.ErrMirrorLimit
	}
	kind := ""
	switch typ {
	case 1:
		kind = "commit"
	case 2:
		kind = "tree"
	case 3:
		kind = "blob"
	case 4:
		kind = "tag"
	case 6, 7:
		base, err := s.object(baseID, depth+1, active)
		if err != nil {
			release()
			return empty, err
		}
		defer base.release()
		result, extra, err := s.delta(base.data, data)
		if err != nil {
			release()
			return empty, err
		}
		oldRelease := release
		release = func() { oldRelease(); extra() }
		data = result
		kind = base.kind
	default:
		release()
		return empty, errMirrorCorrupt
	}
	if objectID(data, kind) != id {
		release()
		return empty, errMirrorCorrupt
	}
	return mirrorObject{kind, data, release}, nil
}

// Implements io.ByteReader so zlib cannot read ahead into another object.
type packBytes struct {
	r io.Reader
	n int64
}

func newPackBytes(r io.Reader) *packBytes       { return &packBytes{r: r} }
func (b *packBytes) Read(p []byte) (int, error) { n, e := b.r.Read(p); b.n += int64(n); return n, e }
func (b *packBytes) ReadByte() (byte, error) {
	v := [1]byte{}
	_, e := io.ReadFull(b, v[:])
	return v[0], e
}
func deltaInt(b []byte, pos *int) (uint64, error) {
	var v uint64
	for shift := uint(0); shift <= 63; shift += 7 {
		if *pos >= len(b) {
			return 0, errMirrorCorrupt
		}
		c := b[*pos]
		*pos++
		if shift == 63 && c > 1 {
			return 0, errMirrorCorrupt
		}
		v |= uint64(c&127) << shift
		if c&128 == 0 {
			return v, nil
		}
	}
	return 0, errMirrorCorrupt
}
func (s *mirrorScan) delta(base, b []byte) ([]byte, func(), error) {
	pos := 0
	n, e := deltaInt(b, &pos)
	if e != nil || n != uint64(len(base)) {
		return nil, nil, errMirrorCorrupt
	}
	size, e := deltaInt(b, &pos)
	if e != nil {
		return nil, nil, e
	}
	if size > mirrorObjectMax {
		return nil, nil, gate.ErrMirrorLimit
	}
	release, e := s.reserve(int64(size))
	if e != nil {
		return nil, nil, e
	}
	out := make([]byte, 0, int(size))
	fail := func() ([]byte, func(), error) { release(); return nil, nil, errMirrorCorrupt }
	for pos < len(b) {
		op := b[pos]
		pos++
		if op == 0 {
			return fail()
		}
		if op&128 == 0 {
			count := int(op)
			if count > len(b)-pos || len(out)+count > int(size) {
				return fail()
			}
			out = append(out, b[pos:pos+count]...)
			pos += count
			continue
		}
		offset, count := uint64(0), uint64(0)
		for j := range 7 {
			if op&(1<<j) == 0 {
				continue
			}
			if pos >= len(b) {
				return fail()
			}
			v := uint64(b[pos])
			pos++
			if j < 4 {
				offset |= v << uint(j*8)
			} else {
				count |= v << uint((j-4)*8)
			}
		}
		if count == 0 {
			count = 65536
		}
		if offset > uint64(len(base)) || count > uint64(len(base))-offset || uint64(len(out))+count > size {
			return fail()
		}
		out = append(out, base[offset:offset+count]...)
	}
	if uint64(len(out)) != size {
		return fail()
	}
	s.expanded += int64(len(out))
	if s.expanded > 512<<20 {
		release()
		return nil, nil, gate.ErrMirrorLimit
	}
	return out, release, nil
}

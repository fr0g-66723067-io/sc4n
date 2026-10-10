package main

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"time"
)

// archiveFixtures writes the container/compression fixtures.
//
// Every fixture reproduces a published evasion or a scanner property that is
// invisible without a real byte stream: a deflate bomb (ratio cap), a zip_slip
// member list, a local-header/central-directory name disagreement, a duplicate
// member, a CRC-corrupted member, and gzip(bzip2(pickle)) — the modelscan
// double-compression bypass. The zip bytes are assembled by hand because
// archive/zip's writer refuses to emit the malformed shapes (a mismatched local
// name, a wrong CRC) that the fixtures exist to exercise.
func init() {
	register(contributor{
		name:         "archive",
		fixtures:     archiveFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) { return archiveExpectations() },
	})
}

func archiveFixtures(f *fixtureSet) {
	// --- deflate bomb ------------------------------------------------------------
	// 4 MiB of zeros compressed with deflate: a few kilobytes that expand past
	// MaxRatio (default 200), so the ratio cap fires before the member is read.
	f.add("zip_bomb.zip", arcZip([]arcZipSpec{{
		name:   "bomb.bin",
		data:   make([]byte, 4<<20),
		method: 8,
	}}))

	// --- ratio cap firing mid-member: the bytes already read must still be scanned
	// A deflate member whose payload is a REDUCE-bearing pickle followed by 4 MiB
	// of zeros. The ratio cap fires after the pickle prefix has been read, and
	// those bytes must still be dispatched: the first bytes of a member are where
	// an attacker puts the payload, so discarding them loses exactly the finding
	// the member was there to carry.
	f.add("zip_ratio_cap_prefix.zip", arcZip([]arcZipSpec{{
		name:   "archive/data.pkl",
		data:   append(arcGadgetPickle(), make([]byte, 4<<20)...),
		method: 8,
	}}))

	// --- zip_slip: traversal + symlink -------------------------------------------
	// A ".." member and a symlink member whose target is an absolute path: the
	// classic zip_slip pair (CWE-22 / CWE-59).
	symlinkMode := uint32(0o120777)
	f.add("zip_slip.zip", arcZip([]arcZipSpec{
		{name: "../evil.txt", data: []byte("pwned\n"), method: 0},
		{name: "link", data: []byte("/etc/passwd"), method: 0, mode: symlinkMode},
	}))

	// --- local header vs central directory name ----------------------------------
	// The local header calls the member evil.txt while the directory calls it
	// good.txt: a scanner that reads one name and a loader that uses the other see
	// two different files.
	f.add("zip_name_mismatch.zip", arcZip([]arcZipSpec{{
		name:      "good.txt",
		localName: "evil.txt",
		data:      []byte("hello\n"),
		method:    0,
	}}))

	// --- duplicate member name ---------------------------------------------------
	f.add("zip_duplicate.zip", arcZip([]arcZipSpec{
		{name: "same.txt", data: []byte("first\n"), method: 0},
		{name: "same.txt", data: []byte("second\n"), method: 0},
	}))

	// --- corrupt member: wrong CRC-32 --------------------------------------------
	f.add("zip_corrupt_member.zip", arcZip([]arcZipSpec{{
		name:     "broken.bin",
		data:     []byte("not what the crc says\n"),
		method:   0,
		crc:      0xdeadbeef,
		crcFixed: true,
	}}))

	// --- gzip(bzip2(pickle)): the modelscan double-compression bypass -------------
	// The bzip2 layer is a fixed literal because the standard library has a bzip2
	// reader but no writer. Reference: the modelscan gzip-then-bz2 bypass.
	f.add("double_compressed.pkl.gz.bz2", arcGzip(arcGadgetBzip2()))

	// --- unsupported compression -------------------------------------------------
	// zstd magic followed by opaque bytes: recognised, named, and reported as not
	// decompressed. sc4n never shells out to a decompressor.
	zst := []byte{0x28, 0xb5, 0x2f, 0xfd}
	zst = append(zst, make([]byte, 64)...)
	f.add("unsupported.zst", zst)

	// --- tar with a traversal name and a symlink --------------------------------
	f.add("tar_links.tar", arcTar())

	// --- large stored member: content must still be parsed ----------------------
	// A stored (uncompressed) member larger than MaxStringBlob (16 MiB default):
	// the walker hands it to the parser as a zero-copy Section rather than a
	// buffer or a temp file, and the safetensors content rules still fire.
	f.add("zip_large_safetensors.zip", arcZip([]arcZipSpec{{
		name:   "model.safetensors",
		data:   arcSafetensorsTrailing(17 << 20),
		method: 0,
	}}))

	// --- benign: an ordinary zip of a text file ----------------------------------
	f.add("benign/plain.zip", arcZip([]arcZipSpec{{
		name:   "data.txt",
		data:   []byte("sc4n benign archive fixture\nthe quick brown fox\n"),
		method: 8,
	}}))

	// --- zip64 end-of-central-directory record, non-saturated 32-bit fields ------
	// Python's zipfile (and therefore torch.save and HF's Trainer) writes a zip64
	// end-of-central-directory record and its locator even when every value fits
	// in 32 bits. Deriving the prefix base from the EOCD instead of from the
	// record that follows the directory put the directory start inside the
	// directory itself, so the whole archive was reported unparseable and the
	// members — the only place the payload lives — were never opened.
	f.add("archive/training_args_zip64.bin", arcZipWithZip64([]arcZipSpec{
		{name: "training_args/data.pkl", data: arcGadgetPickle(), method: 0},
		{name: "training_args/byteorder", data: []byte("little"), method: 0},
	}))
}

// arcSafetensorsTrailing returns a safetensors stream whose single U8 tensor
// declares n bytes and whose data section carries 16 extra trailing bytes, so a
// parser that actually reads the member reports SC4N-SAFETENSORS-TRAILING-DATA.
// It is a valid header followed by a data buffer, so the only anomaly is the tail.
func arcSafetensorsTrailing(n int) []byte {
	header := `{"a":{"dtype":"U8","shape":[` + arcItoa(n) + `],"data_offsets":[0,` + arcItoa(n) + `]}}`
	out := make([]byte, 8, 8+len(header)+n+16)
	binary.LittleEndian.PutUint64(out, uint64(len(header)))
	out = append(out, header...)
	out = append(out, make([]byte, n+16)...)
	return out
}

func arcItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// arcGadgetPickle is the canonical protocol-4 os.system payload: PROTO 4,
// SHORT_BINUNICODE "os", SHORT_BINUNICODE "system", STACK_GLOBAL,
// SHORT_BINUNICODE "id", TUPLE1, REDUCE, STOP.
func arcGadgetPickle() []byte {
	return []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
}

// arcGadgetBzip2 is bzip2 -9 of arcGadgetPickle(), embedded as a literal because
// Go's standard library can decompress bzip2 but cannot produce it. It is fixed
// bytes, so fixture generation stays deterministic.
func arcGadgetBzip2() []byte {
	const h = "425a6839314159265359662104e000000853e015000001100006228c2042040800200022268d34643c90a1a698002815cc87e299053c28b57c5dc914e1424198841380"
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("archive fixture: bad bzip2 literal: " + err.Error())
	}
	return b
}

func arcGzip(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func arcDeflate(b []byte) []byte {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(b); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func arcTar() []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	add := func(hdr *tar.Header, body []byte) {
		hdr.Format = tar.FormatUSTAR
		hdr.ModTime = time.Unix(0, 0)
		hdr.Uid, hdr.Gid = 0, 0
		hdr.Uname, hdr.Gname = "", ""
		if err := w.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if len(body) > 0 {
			if _, err := w.Write(body); err != nil {
				panic(err)
			}
		}
	}
	add(&tar.Header{Name: "data.txt", Mode: 0o644, Size: int64(len("plain\n")), Typeflag: tar.TypeReg}, []byte("plain\n"))
	add(&tar.Header{Name: "link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, nil)
	add(&tar.Header{Name: "../evil.txt", Mode: 0o644, Size: int64(len("pwned\n")), Typeflag: tar.TypeReg}, []byte("pwned\n"))
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// arcZipSpec describes one member for the hand-built zip writer.
type arcZipSpec struct {
	name      string
	localName string // defaults to name
	data      []byte
	method    uint16 // 0 stored, 8 deflate
	mode      uint32 // unix mode, high 16 bits of external attributes
	crc       uint32
	crcFixed  bool // use crc as given rather than computing it
}

func arcZip(specs []arcZipSpec) []byte {
	var buf bytes.Buffer
	type cd struct {
		name, localName string
		method          uint16
		crc             uint32
		comp, uncomp    uint32
		mode            uint32
		off             uint32
	}
	recs := make([]cd, len(specs))
	for i, sp := range specs {
		payload := sp.data
		if sp.method == 8 {
			payload = arcDeflate(sp.data)
		}
		crc := sp.crc
		if !sp.crcFixed {
			crc = crc32.ChecksumIEEE(sp.data)
		}
		ln := sp.localName
		if ln == "" {
			ln = sp.name
		}
		off := uint32(buf.Len())
		arcWriteLocal(&buf, sp.method, crc, uint32(len(payload)), uint32(len(sp.data)), ln)
		buf.Write(payload)
		recs[i] = cd{
			name: sp.name, localName: ln, method: sp.method, crc: crc,
			comp: uint32(len(payload)), uncomp: uint32(len(sp.data)),
			mode: sp.mode, off: off,
		}
	}
	cdOff := uint32(buf.Len())
	for _, r := range recs {
		arcWriteCentral(&buf, r.name, r.method, r.crc, r.comp, r.uncomp, r.mode, r.off)
	}
	cdSize := uint32(buf.Len()) - cdOff
	arcWriteEOCD(&buf, len(recs), cdSize, cdOff)
	return buf.Bytes()
}

func arcWriteLocal(buf *bytes.Buffer, method uint16, crc, comp, uncomp uint32, name string) {
	var b [30]byte
	binary.LittleEndian.PutUint32(b[0:], 0x04034b50)
	binary.LittleEndian.PutUint16(b[4:], 20)
	binary.LittleEndian.PutUint16(b[6:], 0) // flags
	binary.LittleEndian.PutUint16(b[8:], method)
	binary.LittleEndian.PutUint16(b[10:], 0) // time
	binary.LittleEndian.PutUint16(b[12:], 0) // date
	binary.LittleEndian.PutUint32(b[14:], crc)
	binary.LittleEndian.PutUint32(b[18:], comp)
	binary.LittleEndian.PutUint32(b[22:], uncomp)
	binary.LittleEndian.PutUint16(b[26:], uint16(len(name)))
	binary.LittleEndian.PutUint16(b[28:], 0) // extra len
	buf.Write(b[:])
	buf.WriteString(name)
}

func arcWriteCentral(buf *bytes.Buffer, name string, method uint16, crc, comp, uncomp, mode, off uint32) {
	var b [46]byte
	binary.LittleEndian.PutUint32(b[0:], 0x02014b50)
	binary.LittleEndian.PutUint16(b[4:], (3<<8)|20) // made by unix
	binary.LittleEndian.PutUint16(b[6:], 20)
	binary.LittleEndian.PutUint16(b[8:], 0) // flags
	binary.LittleEndian.PutUint16(b[10:], method)
	binary.LittleEndian.PutUint16(b[12:], 0)
	binary.LittleEndian.PutUint16(b[14:], 0)
	binary.LittleEndian.PutUint32(b[16:], crc)
	binary.LittleEndian.PutUint32(b[20:], comp)
	binary.LittleEndian.PutUint32(b[24:], uncomp)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(name)))
	binary.LittleEndian.PutUint16(b[30:], 0) // extra
	binary.LittleEndian.PutUint16(b[32:], 0) // comment
	binary.LittleEndian.PutUint16(b[34:], 0) // disk
	binary.LittleEndian.PutUint16(b[36:], 0) // internal attrs
	binary.LittleEndian.PutUint32(b[38:], mode<<16)
	binary.LittleEndian.PutUint32(b[42:], off)
	buf.Write(b[:])
	buf.WriteString(name)
}

func arcWriteEOCD(buf *bytes.Buffer, entries int, cdSize, cdOff uint32) {
	var b [22]byte
	binary.LittleEndian.PutUint32(b[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(b[8:], uint16(entries))
	binary.LittleEndian.PutUint16(b[10:], uint16(entries))
	binary.LittleEndian.PutUint32(b[12:], cdSize)
	binary.LittleEndian.PutUint32(b[16:], cdOff)
	buf.Write(b[:])
}

// arcZipWithZip64 writes the layout Python's zipfile emits for an archive it
// decided to write with a zip64 record: local records, the central directory, a
// zip64 end-of-central-directory record, its locator, and an EOCD whose 32-bit
// fields still carry the real (non-saturated) values. Only the extra record
// before the EOCD distinguishes it from arcZip.
func arcZipWithZip64(specs []arcZipSpec) []byte {
	var buf bytes.Buffer
	type rec struct {
		name              string
		method            uint16
		crc, comp, uncomp uint32
		off               uint32
	}
	recs := make([]rec, len(specs))
	for i, sp := range specs {
		payload := sp.data
		if sp.method == 8 {
			payload = arcDeflate(sp.data)
		}
		crc := crc32.ChecksumIEEE(sp.data)
		off := uint32(buf.Len())
		arcWriteLocal(&buf, sp.method, crc, uint32(len(payload)), uint32(len(sp.data)), sp.name)
		buf.Write(payload)
		recs[i] = rec{name: sp.name, method: sp.method, crc: crc,
			comp: uint32(len(payload)), uncomp: uint32(len(sp.data)), off: off}
	}
	cdOff := uint32(buf.Len())
	for _, r := range recs {
		arcWriteCentral(&buf, r.name, r.method, r.crc, r.comp, r.uncomp, 0, r.off)
	}
	cdSize := uint32(buf.Len()) - cdOff

	// zip64 EOCD record: 56 bytes total, 44 after the size field. Entries and
	// directory fields are 64-bit; the record offset is what the reader needs.
	var z [56]byte
	binary.LittleEndian.PutUint32(z[0:], 0x06064b50)
	binary.LittleEndian.PutUint64(z[4:], 44)
	binary.LittleEndian.PutUint16(z[12:], 45) // version made by
	binary.LittleEndian.PutUint16(z[14:], 45) // version needed
	binary.LittleEndian.PutUint64(z[24:], uint64(len(recs)))
	binary.LittleEndian.PutUint64(z[32:], uint64(len(recs)))
	binary.LittleEndian.PutUint64(z[40:], uint64(cdSize))
	binary.LittleEndian.PutUint64(z[48:], uint64(cdOff))
	z64Off := uint32(buf.Len())
	buf.Write(z[:])

	var loc [20]byte
	binary.LittleEndian.PutUint32(loc[0:], 0x07064b50)
	binary.LittleEndian.PutUint64(loc[8:], uint64(z64Off))
	binary.LittleEndian.PutUint32(loc[16:], 1)
	buf.Write(loc[:])

	arcWriteEOCD(&buf, len(recs), cdSize, cdOff)
	return buf.Bytes()
}

// archiveExpectations is the rule contract for the container fixtures. The
// "forbid" half is deliberately sparse here: the point of these fixtures is that
// a member rule fires and the walk continues, so a missing rule is the failure
// worth asserting, not an extra finding.
func archiveExpectations() (map[string]expectation, map[string]expectation) {
	malicious := map[string]expectation{
		"zip_bomb.zip": {
			Expect: []string{"SC4N-LIMIT-RATIO"},
			Notes: "4 MiB of zeros deflate-compressed to a few kilobytes: the ratio cap " +
				"fires before the member is decompressed, so the scan is fast and bounded.",
		},
		"zip_ratio_cap_prefix.zip": {
			Expect: []string{"SC4N-LIMIT-RATIO", "SC4N-PICKLE-GLOBAL-CRITICAL"},
			Notes: "A REDUCE-bearing pickle followed by 4 MiB of zeros inside one deflate " +
				"member. The ratio cap fires mid-member, so the prefix that was already read " +
				"has to be dispatched anyway: a cap must bound the work, never hide the " +
				"payload that comes first.",
		},
		"zip_slip.zip": {
			Expect: []string{"SC4N-ARCHIVE-PATH", "SC4N-ARCHIVE-LINK"},
			Notes: "A '../evil.txt' member (CWE-22) and a symlink member pointing at " +
				"/etc/passwd (CWE-59): the zip_slip pair. sc4n never extracts, so these " +
				"are reported from the directory metadata.",
		},
		"zip_name_mismatch.zip": {
			Expect: []string{"SC4N-ARCHIVE-NAME-MISMATCH"},
			Notes: "The local header calls the member evil.txt and the central directory " +
				"calls it good.txt, so a scanner reading one name and a loader using the " +
				"other disagree about what the member is.",
		},
		"zip_duplicate.zip": {
			Expect: []string{"SC4N-ARCHIVE-DUPLICATE-NAME"},
			Notes: "Two members named same.txt; which copy a loader uses is " +
				"extractor-dependent, so the scan and the load can differ.",
		},
		"zip_corrupt_member.zip": {
			Expect: []string{"SC4N-ARCHIVE-CRC"},
			Notes: "The member's bytes do not hash to its recorded CRC-32: the archive " +
				"was edited after it was written (or is corrupt).",
		},
		"double_compressed.pkl.gz.bz2": {
			Expect: []string{"SC4N-ARCHIVE-NESTED-COMPRESSION", "SC4N-PICKLE-GLOBAL-CRITICAL"},
			Notes: "gzip(bzip2(os.system pickle)): the published modelscan " +
				"double-compression bypass. sc4n recurses through both wrappers and " +
				"reaches the pickle's global rule.",
		},
		"unsupported.zst": {
			Expect: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"},
			Notes: "zstd magic with opaque payload: recognised, named, and reported as " +
				"NOT decompressed rather than silently skipped, because the standard " +
				"library has no zstd decoder and sc4n never shells out.",
		},
		"tar_links.tar": {
			Expect: []string{"SC4N-ARCHIVE-PATH", "SC4N-ARCHIVE-LINK"},
			Notes:  "A tar with a '../evil.txt' member and a symlink to /etc/passwd.",
		},
		"zip_large_safetensors.zip": {
			Expect: []string{"SC4N-SAFETENSORS-TRAILING-DATA"},
			Notes: "A stored (uncompressed) zip member of ~17 MiB — above the 16 MiB " +
				"MaxStringBlob — holding a valid safetensors with 16 trailing bytes. " +
				"It proves the member's *content* was parsed (zero-copy Section, no " +
				"buffer, no temp file), not merely listed.",
		},
		"archive/training_args_zip64.bin": {
			Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-PARSE-FAILED", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A zip carrying a zip64 end-of-central-directory record with " +
				"non-saturated 32-bit fields (Python's zipfile and torch.save write " +
				"this shape) and the HF Trainer member layout " +
				"training_args/{data.pkl,byteorder}. The prefix base must come from the " +
				"record that follows the directory, not from the EOCD, or the archive " +
				"is reported unparseable and the members are never opened. Both the " +
				"parse failure and the extension mismatch are forbidden: .bin accepts a " +
				"zip because torch.load does.",
		},
	}
	benign := map[string]expectation{
		"benign/plain.zip": {
			Notes: "A deflate-compressed text file in an ordinary zip: no traversal, no " +
				"links, a correct CRC, and a member that is plain text.",
		},
	}
	return malicious, benign
}

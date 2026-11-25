package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Tar type flags are re-exported as untyped constants so the walker does not
// carry the archive/tar import into every branch.
const (
	tarTypeReg  = tar.TypeReg
	tarTypeRegA = tar.TypeRegA
)

func newTarReader(s source.Source) *tar.Reader { return tar.NewReader(s.Reader(0)) }

// isV7Tar reports whether s begins with a valid V7 (pre-USTAR) 512-byte tar
// header. V7 headers carry no "ustar" magic at offset 257, so the check verifies
// a non-empty printable name, a valid octal checksum matching the header bytes, a
// V7 typeflag, and a clean parse by archive/tar.
func isV7Tar(s source.Source) bool {
	if s == nil || s.Size() < 512 {
		return false
	}
	b, err := s.Bytes(0, 512)
	if len(b) < 512 {
		_ = err
		return false
	}
	if b[0] == 0 {
		return false
	}
	// Require a printable non-empty name before the first NUL so binary blobs
	// that happen to match the 16-bit header checksum are not claimed.
	for i := 0; i < 100 && b[i] != 0; i++ {
		if b[i] < 0x20 || b[i] >= 0x7f {
			return false
		}
	}
	switch b[156] {
	case 0, '0', '1', '2', '3', '4', '5', '6', '7':
	default:
		return false
	}
	// Verify checksum field contains octal digits before handing to archive/tar.
	hasDigit := false
	for _, c := range b[148:156] {
		if c >= '0' && c <= '7' {
			hasDigit = true
		} else if c != ' ' && c != 0 {
			return false
		}
	}
	if !hasDigit {
		return false
	}
	hdr, terr := tar.NewReader(bytes.NewReader(b)).Next()
	return terr == nil && hdr != nil && hdr.Name != "" && hdr.Size >= 0
}

// collectTar reads the tar header stream once, without reading any member data
// (archive/tar skips unread member data on the next Next call).
func collectTar(s source.Source, l limits.Limits) (Members, error) {
	tr := newTarReader(s)
	ms := Members{Format: artifact.FormatTar}
	max := l.MaxEntries
	if max <= 0 {
		max = limits.Default().MaxEntries
	}
	nameCap := retainedCap(l)
	retained := int64(0)
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed tar header cannot be resynchronised: record the
			// failure as a member error and stop, having kept everything read so
			// far so it is still checked.
			ms.Members = append(ms.Members, Member{
				Name:     "<malformed tar header>",
				Index:    i,
				src:      srcTar,
				localErr: err.Error(),
				IsDir:    true, // do not attempt to open it
			})
			break
		}
		if len(ms.Members) >= max {
			ms.Truncated = true
			break
		}
		retained += int64(len(hdr.Name)) + int64(len(hdr.Linkname))
		if retained > nameCap {
			ms.NamesCapped = true
			ms.NameBytes = retained
			break
		}
		ms.Members = append(ms.Members, tarMember(hdr, i))
	}
	return ms, nil
}

func tarMember(hdr *tar.Header, idx int) Member {
	m := Member{
		Name:           hdr.Name,
		Index:          idx,
		Size:           hdr.Size,
		CompressedSize: hdr.Size,
		Mode:           uint32(hdr.Mode),
		Method:         0,
		Link:           hdr.Linkname,
		src:            srcTar,
	}
	switch hdr.Typeflag {
	case tar.TypeSymlink:
		m.LinkKind = "symlink"
	case tar.TypeLink:
		m.LinkKind = "hardlink"
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		m.LinkKind = "device"
	case tar.TypeDir:
		m.IsDir = true
	}
	return m
}

// openTarMember returns a reader over one tar member's data. A tar is a forward
// stream, so the reader is re-created and advanced to the member's index; this is
// only used for on-demand Open, while Scan walks the stream once.
func openTarMember(s source.Source, l limits.Limits, m Member) (io.ReadCloser, error) {
	tr := newTarReader(s)
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("archive: tar member %q not found", m.Name)
		}
		if err != nil {
			return nil, err
		}
		if i != m.Index {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, errors.New("archive: tar member is not a regular file")
		}
		capBytes := l.MaxDecompressedBytes
		if capBytes <= 0 {
			capBytes = limits.Default().MaxDecompressedBytes
		}
		lr := &limitReader{r: tr, remaining: capBytes, rule: limits.RuleDecompressed, limit: "MaxDecompressedBytes", cap: capBytes, detail: "member " + m.Name}
		return io.NopCloser(lr), nil
	}
}

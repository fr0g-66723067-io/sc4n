// Package artifact decides what a byte range is and which parser runs over it.
//
// Two rules drive the design:
//
//   - dispatch is by content, never by extension. The extension is recorded as a
//     hint, and a disagreement between the sniffed format and the extension is
//     itself a finding (SC4N-FORMAT-EXTENSION-MISMATCH), because "rename it to
//     .bin" is a documented evasion against extension-driven scanners.
//   - a format's knowledge lives with its parser. The magics that are unambiguous
//     live in this package's table; anything that needs a real parse to decide
//     (zip member names for torch/keras/.pt2, the safetensors length+JSON shape,
//     a full pickle opcode walk, ONNX vs SavedModel vs CoreML) is registered by
//     the owning package through RegisterSniffer, at a priority that puts the
//     cheap unambiguous checks first.
package artifact

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Format identifies a container or serialisation format sc4n understands.
type Format uint8

const (
	FormatUnknown Format = iota

	// Pickle family.
	FormatPickle      // a bare pickle stream
	FormatJoblib      // pickle whose ndarrays are joblib wrappers
	FormatTorchNew    // zip: data.pkl + data/*
	FormatTorchLegacy // MAGIC_NUMBER + pickles + storage bytes
	FormatTorchScript // zip with code/**/*.py
	FormatPT2         // zip with archive_format="pt2"
	FormatPTE         // PyTorch Mobile / ExecuTorch flatbuffer

	// Numeric.
	FormatNPY // \x93NUMPY
	FormatNPZ // zip of .npy members
	FormatMsgpack
	FormatXGBoostUBJ

	// Model formats with a parser.
	FormatSafetensors
	FormatGGUF
	FormatONNX
	FormatTFLite
	FormatHDF5
	FormatKeras
	FormatTFSavedModel
	FormatTFCheckpoint
	FormatCoreML

	// Containers and compression.
	FormatZip
	FormatTar
	FormatGzip
	FormatZlib
	FormatBzip2
	FormatXz
	FormatLzma
	FormatLz4
	FormatZstd
	FormatSevenZip
	FormatRar
	FormatZlibJoblibLegacy // joblib's "ZF" legacy format

	// Code and text.
	FormatPython
	FormatNotebook
	FormatJinja
	FormatJSON
	FormatJSONLines
	FormatMarkdown
	FormatYAML
	FormatText

	// Executables.
	FormatNative // ELF / PE / Mach-O / OLE, identified by magic
)

var formatNames = map[Format]string{
	FormatUnknown:          "unknown",
	FormatPickle:           "pickle",
	FormatJoblib:           "joblib",
	FormatTorchNew:         "torch-zip",
	FormatTorchLegacy:      "torch-legacy",
	FormatTorchScript:      "torchscript",
	FormatPT2:              "pt2",
	FormatPTE:              "pte",
	FormatNPY:              "npy",
	FormatNPZ:              "npz",
	FormatMsgpack:          "msgpack",
	FormatXGBoostUBJ:       "xgboost-ubj",
	FormatSafetensors:      "safetensors",
	FormatGGUF:             "gguf",
	FormatONNX:             "onnx",
	FormatTFLite:           "tflite",
	FormatHDF5:             "hdf5",
	FormatKeras:            "keras",
	FormatTFSavedModel:     "tf-savedmodel",
	FormatTFCheckpoint:     "tf-checkpoint",
	FormatCoreML:           "coreml",
	FormatZip:              "zip",
	FormatTar:              "tar",
	FormatGzip:             "gzip",
	FormatZlib:             "zlib",
	FormatBzip2:            "bzip2",
	FormatXz:               "xz",
	FormatLzma:             "lzma",
	FormatLz4:              "lz4",
	FormatZstd:             "zstd",
	FormatSevenZip:         "7z",
	FormatRar:              "rar",
	FormatZlibJoblibLegacy: "joblib-legacy-zf",
	FormatPython:           "python",
	FormatNotebook:         "notebook",
	FormatJinja:            "jinja",
	FormatJSON:             "json",
	FormatJSONLines:        "jsonl",
	FormatMarkdown:         "markdown",
	FormatYAML:             "yaml",
	FormatText:             "text",
	FormatNative:           "native",
}

func (f Format) String() string {
	if n, ok := formatNames[f]; ok {
		return n
	}
	return fmt.Sprintf("format(%d)", int(f))
}

// Depth describes how far sc4n looks inside a format, and is what `sc4n formats`
// prints so that "no findings" is never mistaken for "fully analysed".
type Depth uint8

const (
	// DepthNone: recognised but not parsed.
	DepthNone Depth = iota
	// DepthShallow: header/identifier validation plus a string and native-magic
	// scan of the whole artifact; the payload is not decoded.
	DepthShallow
	// DepthStructural: the format's own structures are walked and validated.
	DepthStructural
	// DepthDeep: structures walked *and* embedded code/pickles handed to their
	// own engines.
	DepthDeep
)

func (d Depth) String() string {
	switch d {
	case DepthNone:
		return "none"
	case DepthShallow:
		return "shallow"
	case DepthStructural:
		return "structural"
	case DepthDeep:
		return "deep"
	}
	return "unknown"
}

// Info describes one format for the `sc4n formats` capability table.
type Info struct {
	Format Format
	// Magic is the human-readable signature, e.g. "PK\\x03\\x04".
	Magic string
	Depth Depth
	// Container is true when members are recursively dispatched.
	Container bool
	// Notes states what the depth means for this format and, where relevant,
	// what is deliberately not done. It becomes a documentation line, so it must
	// stay honest about gaps (for example HDF5's missing object-header reader).
	Notes string
}

var (
	formatsMu sync.Mutex
	formats   = map[Format]Info{}
)

// RegisterFormat records a format's capability row. It panics when a format is
// described twice, because two rows for one format means the capability table
// lies about what was scanned. FormatUnknown may be registered explicitly (it is
// how "no sniffer matched" documents itself); the duplicate guard doubles as the
// check for a forgotten Format field, since a zero-valued Format collides with
// that row.
func RegisterFormat(i Info) {
	if i.Notes == "" {
		panic(fmt.Sprintf("artifact: format %s has no capability note", i.Format))
	}
	formatsMu.Lock()
	defer formatsMu.Unlock()
	if _, dup := formats[i.Format]; dup {
		panic(fmt.Sprintf("artifact: format %s registered twice", i.Format))
	}
	formats[i.Format] = i
}

// FormatInfo returns the registered capability row for f.
func FormatInfo(f Format) (Info, bool) {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	i, ok := formats[f]
	return i, ok
}

// AllFormats returns every registered capability row, sorted by name.
func AllFormats() []Info {
	formatsMu.Lock()
	out := make([]Info, 0, len(formats))
	for _, i := range formats {
		out = append(out, i)
	}
	formatsMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Format.String() < out[j].Format.String() })
	return out
}

// SniffFunc reports the format of s if it recognises it. A sniffer MUST NOT
// allocate beyond the header region, MUST honour l, and MUST NOT panic.
type SniffFunc func(s source.Source, l limits.Limits) (Format, bool)

type sniffer struct {
	name string
	prio int
	fn   SniffFunc
}

var (
	sniffMu  sync.Mutex
	sniffers []sniffer
)

// RegisterSniffer adds a content sniffer. Higher prio runs first; ties break on
// name so the order is stable across builds. Registering the same name twice is a
// programmer error and panics.
func RegisterSniffer(name string, prio int, fn SniffFunc) {
	if name == "" {
		panic("artifact: unnamed sniffer")
	}
	sniffMu.Lock()
	defer sniffMu.Unlock()
	for _, s := range sniffers {
		if s.name == name {
			panic("artifact: sniffer " + name + " registered twice")
		}
	}
	sniffers = append(sniffers, sniffer{name: name, prio: prio, fn: fn})
}

// Sniff runs every registered sniffer in priority order and returns the first
// match, with the name of the sniffer that matched (for -v diagnostics and for
// SC4N-FORMAT-AMBIGUOUS).
func Sniff(s source.Source, l limits.Limits) (Format, string) {
	sniffMu.Lock()
	ordered := make([]sniffer, len(sniffers))
	copy(ordered, sniffers)
	sniffMu.Unlock()
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].prio != ordered[j].prio {
			return ordered[i].prio > ordered[j].prio
		}
		return ordered[i].name < ordered[j].name
	})
	for _, sn := range ordered {
		if f, ok := sn.fn(s, l); ok {
			return f, sn.name
		}
	}
	return FormatUnknown, ""
}

// extensions maps a lowercase extension (without the dot) to the format a file
// with that extension is expected to be. It is deliberately conservative: an
// extension that legitimately denotes several formats (".pt", ".model", ".json")
// is listed once under its dominant meaning, and the mismatch rule only fires
// when the *sniffed* format has no plausible relationship with any meaning of the
// extension.
//
// ".txt" lists Jinja because it is the untyped text extension: a chat template
// saved as chat_template.txt is a template, and the content sniffer classifies it
// as one, so without this entry every such file reported
// SC4N-FORMAT-EXTENSION-MISMATCH for being what it is.
var extensions = map[string][]Format{
	"pkl":         {FormatPickle, FormatJoblib, FormatZlibJoblibLegacy},
	"pickle":      {FormatPickle, FormatJoblib, FormatZlibJoblibLegacy},
	"pcl":         {FormatPickle},
	"joblib":      {FormatJoblib, FormatZlibJoblibLegacy},
	"pt":          {FormatTorchNew, FormatTorchLegacy, FormatTorchScript, FormatPT2, FormatPickle, FormatSevenZip, FormatZip, FormatNPZ},
	"pth":         {FormatTorchNew, FormatTorchLegacy, FormatPickle, FormatPython},
	"ptl":         {FormatTorchScript, FormatPTE, FormatPickle},
	"pt2":         {FormatPT2, FormatZip},
	"pte":         {FormatPTE},
	"ckpt":        {FormatTorchNew, FormatTorchLegacy, FormatPickle, FormatZip, FormatTFCheckpoint},
	"npy":         {FormatNPY},
	"npz":         {FormatNPZ, FormatZip},
	"bin":         {FormatSafetensors, FormatPickle, FormatNative, FormatText},
	"safetensors": {FormatSafetensors},
	"gguf":        {FormatGGUF},
	"onnx":        {FormatONNX},
	"pb":          {FormatONNX, FormatTFSavedModel},
	"tflite":      {FormatTFLite},
	"h5":          {FormatHDF5},
	"hdf5":        {FormatHDF5},
	"keras":       {FormatKeras, FormatZip, FormatNPZ},
	"mlmodel":     {FormatCoreML},
	"mlpackage":   {FormatCoreML},
	"msgpack":     {FormatMsgpack},
	"ubj":         {FormatXGBoostUBJ},
	"json":        {FormatJSON, FormatXGBoostUBJ, FormatTFSavedModel, FormatNotebook},
	"zip":         {FormatZip, FormatTorchNew, FormatPT2, FormatKeras, FormatNPZ, FormatTorchScript},
	"tar":         {FormatTar},
	"gz":          {FormatGzip},
	"bz2":         {FormatBzip2},
	"xz":          {FormatXz},
	"lz4":         {FormatLz4},
	"zst":         {FormatZstd},
	"7z":          {FormatSevenZip},
	"rar":         {FormatRar},
	"py":          {FormatPython},
	"ipynb":       {FormatNotebook},
	"jinja":       {FormatJinja, FormatText},
	"jinja2":      {FormatJinja, FormatText},
	"j2":          {FormatJinja, FormatText},
	"tmpl":        {FormatJinja, FormatText},
	"md":          {FormatMarkdown, FormatText},
	"yaml":        {FormatYAML, FormatText},
	"yml":         {FormatYAML, FormatText},
	"txt":         {FormatText, FormatJinja},
	"jsonl":       {FormatJSONLines},
	"whl":         {FormatZip, FormatNPZ},
	"so":          {FormatNative},
	"dll":         {FormatNative},
	"dylib":       {FormatNative},
	"exe":         {FormatNative},
	"start":       {FormatText},
}

// ExtensionPlausible reports whether the sniffed format is a plausible content
// for path's extension. An unknown extension is always plausible (there is
// nothing to contradict), which keeps the rule from firing on the many real-world
// files named .model, .weights or .data.
func ExtensionPlausible(path string, f Format) bool {
	i := strings.LastIndexByte(path, '.')
	if i < 0 || i == len(path)-1 {
		return true
	}
	ext := strings.ToLower(path[i+1:])
	want, ok := extensions[ext]
	if !ok {
		return true
	}
	for _, w := range want {
		if w == f {
			return true
		}
	}
	return false
}

package tfmodel

// analyze.go is the shared content analysis for the Keras-family documents: the
// class allowlist, the recursive config walk, the code-string extraction and the
// bounded JSON/path recovery used by the HDF5 reader.
//
// The class allowlist is the Keras counterpart of pickle's weights-only
// allowlist: Keras reconstructs objects by name, so a name outside the set of
// classes Keras itself ships is a class the host must provide, which is the
// surface every safe_mode bypass has used. The two named criticals (Lambda,
// TorchModuleWrapper) are checked before the allowlist because they are
// dangerous even though Keras knows them.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/cards"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/pysrc"
)

// safeClasses is the curated set of Keras-provided class names that a benign
// model document uses. It is intentionally a mixture of exact names and the
// prefix/suffix families below, because Keras spells its layer classes
// systematically (Conv1D..Conv3D, GlobalAveragePooling2D, RandomFlip, the
// preprocessing layers).
var safeClasses = map[string]bool{
	// Models and topology.
	"Sequential": true, "Functional": true, "Model": true, "InputLayer": true,
	// Core layers.
	"Dense": true, "Activation": true, "Dropout": true, "Flatten": true,
	"Reshape": true, "Permute": true, "RepeatVector": true, "Masking": true,
	"Embedding": true, "Rescaling": true,
	// Pooling / pooling helpers not caught by the suffix rules.
	"MaxPool1D": true, "MaxPool2D": true, "MaxPool3D": true,
	"AvgPool1D": true, "AvgPool2D": true, "AvgPool3D": true,
	// Normalisation families.
	"Normalization": true, "Discretization": true, "CategoryEncoding": true,
	"IntegerLookup": true, "StringLookup": true, "TextVectorization": true,
	"Hashing": true,
	// Recurrent helpers.
	"RNN": true, "SimpleRNN": true, "TimeDistributed": true, "Bidirectional": true,
	// Merge layers.
	"Add": true, "Subtract": true, "Multiply": true, "Average": true,
	"Maximum": true, "Minimum": true, "Concatenate": true, "Dot": true,
	// Attention.
	"Attention": true, "AdditiveAttention": true, "MultiHeadAttention": true,
	// Regularisation / noise.
	"GaussianNoise": true, "GaussianDropout": true, "AlphaDropout": true,
	"ActivityRegularization": true, "SpatialDropout1D": true,
	"SpatialDropout2D": true, "SpatialDropout3D": true,
	// Legacy serialization shims a Keras 2 document legitimately carries.
	"TensorFlowOpLayer": true, "TFOpLambda": true, "SlicingOpLambda": true,
	"Identity": true, "Softmax": true,
}

// safeClassPrefixes are the systematically named Keras families.
var safeClassPrefixes = []string{
	"Conv", "SeparableConv", "DepthwiseConv", "UpSampling", "ZeroPadding",
	"Cropping", "GlobalMaxPooling", "GlobalAveragePooling", "MaxPooling",
	"AveragePooling", "Random", "Preprocessing",
}

// safeClassSuffixes are families whose names vary only by rank or backend.
var safeClassSuffixes = []string{
	"Normalization", "Dropout", "Pooling1D", "Pooling2D", "Pooling3D",
}

// internalClasses are names the loader generates for itself; they are not
// reported because the rule that owns the construct (Lambda) already fired.
var internalClasses = map[string]bool{"__lambda__": true}

// kerasClassSafe reports whether name is a class Keras itself provides.
func kerasClassSafe(name string) bool {
	if name == "" || internalClasses[name] {
		return true
	}
	if safeClasses[name] {
		return true
	}
	for _, p := range safeClassPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, s := range safeClassSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// classKeys are the keys that name a class Keras will reconstruct.
var classKeys = map[string]bool{"class_name": true, "registered_name": true}

// codeKeys are the keys whose string values may carry executable code or the
// pieces of a reconstructed function.
var codeKeys = map[string]bool{
	"code": true, "function": true, "function_source": true, "module": true,
	"closure": true, "defaults": true,
}

// scanTextCapped runs the shared card/indicator detectors over one string under
// the MaxStringBlob cap. A value larger than the cap is truncated and the cap is
// reported, because a silent truncation would hide an indicator past the cut.
func scanTextCapped(ctx *artifact.Ctx, base int64, what, s string) {
	if s == "" {
		return
	}
	cap := ctx.Limits.MaxStringBlob
	if cap <= 0 {
		cap = limits.Default().MaxStringBlob
	}
	if int64(len(s)) > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(s)), cap, what)
		s = s[:cap]
	}
	cards.ScanText(ctx.Sink, base, what, s)
}

// analyzeKerasDocument decodes one Keras-family JSON document and applies the
// class allowlist and the code-string extraction to it. A document that does not
// decode is reported and scanned as text, because an unreadable config is exactly
// what a parser must not turn into silence.
func analyzeKerasDocument(ctx *artifact.Ctx, base int64, what string, data []byte) {
	if len(data) == 0 {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		ctx.Sink.Emit(ruleKerasStruct, base, "document "+what+" is not valid JSON: "+err.Error())
		scanTextCapped(ctx, base, what, string(data))
		return
	}
	analyzeKerasValue(ctx, base, what, doc, 0)
}

// maxJSONDepth bounds the recursive walk. Real Keras configs nest well under
// this; the cap stops a pathological document from driving recursion.
const maxJSONDepth = 64

// analyzeKerasValue walks a decoded JSON value. Map keys are visited in sorted
// order so the emission order is deterministic even against a document with many
// classes (the report sorts anyway, but a finding cap must not depend on Go's map
// iteration order).
func analyzeKerasValue(ctx *artifact.Ctx, base int64, what string, v any, depth int) {
	if depth > maxJSONDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := t[k]
			switch {
			case classKeys[k]:
				if name, ok := val.(string); ok {
					checkKerasClass(ctx, base, what, k, name)
				}
			case codeKeys[k]:
				if s, ok := val.(string); ok {
					analyzeCodeValue(ctx, base, what, k, s)
					continue
				}
			}
			analyzeKerasValue(ctx, base, what, val, depth+1)
		}
	case []any:
		for _, e := range t {
			analyzeKerasValue(ctx, base, what, e, depth+1)
		}
	}
}

// checkKerasClass applies the allowlist and the two named criticals. name is
// reduced to its last component first, because registered_name is often written
// as "keras.layers.Dense" or "pkg>Class".
func checkKerasClass(ctx *artifact.Ctx, base int64, what, key, name string) {
	if name == "" {
		return
	}
	short := lastClassComponent(name)
	switch {
	case short == "Lambda":
		ctx.Sink.Emit(ruleKerasLambda, base, key+" Lambda in "+what)
		return
	case short == "TorchModuleWrapper":
		ctx.Sink.Emit(ruleKerasTorchWrapper, base, key+" TorchModuleWrapper in "+what)
		return
	case kerasClassSafe(short):
		return
	}
	ctx.Sink.EmitExtra(ruleKerasClassUnknown, base,
		key+" "+short+" is outside the Keras safe set (in "+what+")",
		map[string]string{"class": short, "source": what})
}

// lastClassComponent reduces a fully-qualified class reference to its final
// component: "keras.layers.Dense" -> "Dense", "pkg>MyLayer" -> "MyLayer".
func lastClassComponent(name string) string {
	if i := strings.IndexAny(name, ">"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// analyzeCodeValue scans one code-shaped string with the shared indicator engine
// and, when the text looks like Python, with the Python analyzer. A `code` value
// is base64 in the Lambda config, so it is decoded first.
func analyzeCodeValue(ctx *artifact.Ctx, base int64, what, key, val string) {
	if val == "" {
		return
	}
	scanTextCapped(ctx, base, key+" in "+what, val)

	text := val
	decoded := false
	if key == "code" {
		if b, ok := decodeBase64Loose(val); ok {
			text = string(b)
			decoded = true
			scanTextCapped(ctx, base, key+" (base64-decoded) in "+what, text)
		}
	}
	if !looksLikePython(text) {
		return
	}
	mctx, ok := ctx.Member(what, artifact.FormatPython)
	if !ok {
		return
	}
	suffix := ""
	if decoded {
		suffix = " (base64-decoded)"
	}
	_ = suffix
	pysrc.Analyze(mctx, []byte(text))
}

// decodeBase64Loose tries the three base64 alphabets a model document uses.
func decodeBase64Loose(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return nil, false
	}
	encs := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, e := range encs {
		if b, err := e.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// pyMarkers are substrings that make it worth handing a string to the Python
// analyzer. The test is deliberately cheap: the analyzer is robust, but running
// it on every metadata string would be wasted work and would turn ordinary
// prose into lexer input.
var pyMarkers = [][]byte{
	[]byte("import "), []byte("def "), []byte("exec("), []byte("eval("),
	[]byte("__import__"), []byte("os."), []byte("subprocess"), []byte("lambda"),
	[]byte("return "), []byte("#!/"), []byte("pickle.load"), []byte("torch.load"),
}

func looksLikePython(b string) bool {
	for _, m := range pyMarkers {
		if bytes.Contains([]byte(b), m) {
			return true
		}
	}
	return false
}

// pathEscapeReason reports why v cannot be a plain relative path inside the model
// directory, or "" when it can. The check runs on the raw value: a '..' that
// path.Clean would erase is still the value the loader sees.
func pathEscapeReason(v string) string {
	if v == "" {
		return ""
	}
	if strings.IndexByte(v, 0) >= 0 {
		return "contains NUL"
	}
	switch {
	case strings.HasPrefix(v, "/"):
		return "absolute path"
	case strings.HasPrefix(v, "~"):
		return "home-relative path"
	case strings.HasPrefix(v, `\\`):
		return "UNC path"
	case len(v) >= 2 && v[1] == ':':
		return "drive letter"
	}
	if i := strings.Index(v, "://"); i > 0 && isSchemePrefix(v[:i]) {
		return "URL"
	}
	if hasDotDot(v) {
		return "'..' segment"
	}
	return ""
}

func isSchemePrefix(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// hasDotDot reports whether v has a ".." segment under either separator.
func hasDotDot(v string) bool {
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// jsonBlob is one JSON object recovered from a byte region.
type jsonBlob struct {
	off int64
	doc any
}

// extractJSONObjects recovers up to max JSON objects from data by attempting a
// decode at each '{'. It is how the shallow HDF5 reader finds model_config
// without an object-header reader: attributes are stored as opaque bytes in the
// object header, and the JSON value is one of them. Each candidate is bounded by
// cap and the walk advances past whatever decoded, so the cost is linear.
func extractJSONObjects(data []byte, cap int64, max int) []jsonBlob {
	var out []jsonBlob
	if cap <= 0 {
		cap = limits.Default().MaxStringBlob
	}
	for i := 0; i < len(data) && len(out) < max; {
		j := bytes.IndexByte(data[i:], '{')
		if j < 0 {
			break
		}
		start := i + j
		dec := json.NewDecoder(bytes.NewReader(data[start:]))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			i = start + 1
			continue
		}
		end := start + int(dec.InputOffset())
		if int64(end-start) > cap {
			i = end
			continue
		}
		if _, ok := v.(map[string]any); ok {
			out = append(out, jsonBlob{off: int64(start), doc: v})
		}
		i = end
	}
	return out
}

// scanExternalPaths reports URL-shaped, absolute and traversal-bearing strings in
// data. HDF5 external links and external storage name a file the loader opens, but
// the value carries no tag without an object-header reader, so the heuristic is
// reported at low confidence.
func scanExternalPaths(ctx *artifact.Ctx, base int64, data []byte) {
	const maxHits = 8
	hits := 0
	for _, run := range printableRuns(data) {
		if hits >= maxHits {
			return
		}
		if len(run) < 4 {
			continue
		}
		why := pathEscapeReason(run)
		if why == "" {
			continue
		}
		ctx.Sink.EmitExtra(ruleHDF5ExternalLink, base,
			why+" string in HDF5 data: "+clip(run, 120),
			map[string]string{"reason": why, "value": clip(run, 120)})
		hits++
	}
}

// printableRuns returns the maximal runs of printable ASCII at least minRun
// bytes long. HDF5 stores names and scalar payloads as NUL-padded or
// length-prefixed ASCII, so a run is the unit worth inspecting.
func printableRuns(data []byte) []string {
	const minRun = 4
	var out []string
	i := 0
	for i < len(data) {
		if !printable(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && printable(data[j]) {
			j++
		}
		if j-i >= minRun {
			out = append(out, string(data[i:j]))
		}
		i = j
	}
	return out
}

func printable(c byte) bool { return c >= 0x20 && c < 0x7f }

// clip shortens an attacker-controlled string for evidence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

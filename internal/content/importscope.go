package content

// Import-scope grading for an auto_map module.
//
// A config's auto_map names a module that Transformers imports when the model is
// loaded with trust_remote_code=True. The capability finding (SC4N-CONFIG-AUTO-MAP)
// says the module is imported. Whether that is merely powerful or actually a
// program depends on what the module's import-time body does, and that is a
// question about the module file - which is usually sitting right next to the
// config in the same repository.
//
// The unsafe corpus ships the canonical case:
// 0xmoose0xmoose0xmoose/rce-test-pickle-001/modeling_malicious.py makes a DNS
// callback inside a top-level try. Importing it runs the callback, so the right
// grade is constructed, and the evidence names the call.

import (
	"io"
	"os"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/malice"
	"github.com/fr0g-66723067-io/sc4n/internal/pysrc"
)

// importScopeRule reads a module that auto_map names and emits the constructed
// grade for each sink its import-time body calls.
//
// rel is the module path relative to the config's directory, without ".py".
// offset is the position of the auto_map reference in the config, so the finding
// points at the entry that causes the import.
func importScopeRule(ctx *artifact.Ctx, name, rel string, offset int64) {
	dir := realDir(name)
	if dir == "" {
		// A config inside a nested container has no directory on the host, so
		// there is no module file to read. The capability finding stands and this
		// grade stays silent rather than guessing from the reference alone.
		return
	}
	src, ok := readModuleFile(ctx, dir, rel+".py")
	if !ok {
		return
	}
	seen := make(map[string]bool, 4)
	for _, s := range pysrc.ModuleScopeSinks(src) {
		if !malice.IsLoadSink(s.Dotted) || seen[s.Dotted] {
			continue
		}
		seen[s.Dotted] = true
		malice.Constructed(ctx.Sink, offset, malice.FamilyImportScope,
			"module "+rel+".py is imported when the model loads (auto_map with trust_remote_code) and calls "+
				s.Dotted+" while it is imported",
			map[string]string{"module": rel + ".py", "callable": s.Dotted, "file": baseName(name)})
	}
}

// readModuleFile reads a module file for analysis.
//
// The read is contained by os.Root, so a symlink in the scanned tree cannot make
// the scanner read a file outside it, and it is capped by MaxStringBlob - a
// truncation is reported through the same limit rule the Python layer uses for
// source, never silently analysed as a prefix.
func readModuleFile(ctx *artifact.Ctx, dir, rel string) ([]byte, bool) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, false
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	cap := ctx.Limits.MaxStringBlob
	if cap <= 0 {
		cap = 1 << 20
	}
	src, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, false
	}
	if int64(len(src)) > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(src)), cap,
			"module "+rel+" truncated before the import-scope analysis")
		src = src[:cap]
	}
	return src, true
}

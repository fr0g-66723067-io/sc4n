package numpy

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The .npy/.npz/joblib rule set.
//
// Calibration context the rules below depend on:
//
//   - numpy.load refuses object arrays unless the caller passes
//     allow_pickle=True (the default has been False since NumPy 1.16.3), and the
//     data section of an object array is an ordinary pickle stream. So a
//     `descr` containing 'O' is not code execution by itself, but it is the
//     documented path that turns `numpy.load` into an unpickler. The finding is
//     `high`, not `critical`, and the rule text says the loader must opt in.
//   - joblib is a pickle container. Its own globals (the ndarray wrappers) are
//     how a *benign* joblib file pickles an array, which is why the wrapper
//     mismatch check is `medium` and why a wrapper name on its own must not be
//     read as a gadget. The genuine attack surface is the payload those wrappers
//     carry, and that payload is handed to the pickle engine rather than
//     classified here.
var (
	// RuleStruct covers the header grammar of a .npy file: the magic and
	// version, the declared header length, the literal dict (descr,
	// fortran_order, shape), the dtype descriptor, and the declared element
	// count against the bytes actually present. It also covers structural
	// failures of an .npz container (a member that cannot be read).
	RuleStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-NUMPY-STRUCT",
		Title:      ".npy/.npz structure violates the format",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20", "CWE-502"},
		Class:      "structure",
		Description: "A malformed .npy header (bad magic, an unknown version, a header length past the " +
			"end of the file, a dict that is not the literal {descr, fortran_order, shape} form, a " +
			"negative dimension), a declared array larger than the bytes actually present, or an .npz " +
			"member that cannot be read. The header is parsed with a literal reader, never eval, so a " +
			"crafted header cannot execute during the scan. numpy's own loader raises on the same " +
			"violations, so this is \"not what the reference loader accepts\" rather than an exploit.",
		Refs: []string{
			"https://numpy.org/doc/stable/reference/generated/numpy.lib.format.html",
			"https://cwe.mitre.org/data/definitions/502.html",
		},
	})

	// RuleObjectArray fires for an object-dtype array, whose data section is a
	// pickle stream.
	RuleObjectArray = report.DefineRule(report.Rule{
		ID:         "SC4N-NUMPY-OBJECT-ARRAY",
		Title:      "Object-dtype .npy array whose data is a pickle stream",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "numpy",
		Description: "The array descriptor contains the object kind 'O', so the data section is a " +
			"pickle stream rather than raw elements. Loading it requires numpy.load(..., " +
			"allow_pickle=True) (the default has been False since NumPy 1.16.3), and that single flag " +
			"is what turns `numpy.load` into an arbitrary-code unpickler. The data section is handed to " +
			"the pickle engine, so any gadget it contains is reported under its own SC4N-PICKLE-* rule; " +
			"this finding exists so the object-array detour is never invisible.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://numpy.org/doc/stable/reference/generated/numpy.load.html",
		},
	})

	// RuleTrailing fires for bytes after the declared array data. The format
	// has no field for them.
	RuleTrailing = report.DefineRule(report.Rule{
		ID:         "SC4N-NUMPY-TRAILING",
		Title:      "Bytes after the declared .npy array",
		Severity:   report.SeverityLow,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "numpy",
		Description: "The declared shape and dtype describe fewer bytes than the file contains, so there " +
			"is an undeclared tail. A .npy file is exactly its header plus its array, so a tail is " +
			"either an append (a polyglot or a second container) or a truncated-but-wrong rewrite. It " +
			"is low because a memmap'd or concatenated producer can leave padding.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	})

	// RuleJoblibMismatch fires when a joblib array wrapper's declared shape and
	// dtype disagree with the payload length appended after the pickle.
	RuleJoblibMismatch = report.DefineRule(report.Rule{
		ID:         "SC4N-JOBLIB-WRAPPER-MISMATCH",
		Title:      "Joblib array payload does not match the wrapper's declared shape",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "joblib",
		Description: "joblib.pickle writes an ndarray as a `NumpyArrayWrapper` (or the legacy " +
			"`NDArrayWrapper`/`ZNDArrayWrapper`) pickle object plus a payload: a one-byte padding " +
			"length, that many 0xff bytes and then dtype.itemsize x count raw bytes. When the payload " +
			"length does not equal the declared size, the gap is exactly where a second object can ride " +
			"behind the array framing. Confidence is medium because joblib computes the count from the " +
			"shape at load time and a wrapper the scanner cannot decode is skipped rather than guessed.",
		Refs: []string{
			"https://joblib.readthedocs.io/en/stable/persistence.html",
			"https://cwe.mitre.org/data/definitions/502.html",
		},
	})
)

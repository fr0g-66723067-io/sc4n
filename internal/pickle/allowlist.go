package pickle

import "strings"

// Allowlist by name, transcribed from PyTorch's weights-only unpickler.
//
// Source: pytorch/torch/_weights_only_unpickler.py at tag v2.7.0
//
//	https://raw.githubusercontent.com/pytorch/pytorch/v2.7.0/torch/_weights_only_unpickler.py
//	_get_allowed_globals()            static dict + five derived families
//	_blocklisted_modules              {"sys", "os", "posix", "nt"}
//	IMPORT_MAPPING / NAME_MAPPING     torch/_utils.py, adapted from CPython Lib/_compat_pickle.py
//
// Why this is the right policy to mirror: the allowlist is the loader most
// users actually get. `torch.load(weights_only=True)` is the default from torch
// 2.6, and it is the only defence between an attacker-supplied pickle and
// `__reduce__`. A scanner that models the *loader's* policy, rather than a
// denylist of things it happens to know about, is what makes the finding
// actionable ("the weights-only unpickler rejects this") instead of advisory
// ("this name looks scary").
//
// Two structural facts are modelled explicitly, because they are the two ways the
// allowlist is bypassed in practice:
//
//  1. the loader decides by *name*, so an allowlisted name is not proof of
//     anything on its own. ShadowPickle (arXiv 2607.17503) reuses an allowlisted
//     `module.name` string, which is why the memo-alias and code-string rules
//     exist and why they do not consult this table for their verdict.
//  2. the loader decides by name *and* then passes attacker-controlled data to
//     the named callable — `GLOBAL collections OrderedDict` + a code string +
//     REDUCE + BUILD is the paper's motivating example, and the callable is
//     allowlisted there. Hence SC4N-PICKLE-CODE-STRING.

// AllowVerdict is the allowlist's opinion of one qualified name.
type AllowVerdict uint8

const (
	// AllowNo: not in the default allowlist. The weights-only unpickler raises
	// unless the user opted in through add_safe_globals.
	AllowNo AllowVerdict = iota
	// AllowDefault: in the default allowlist; loads with weights_only=True.
	AllowDefault
	// AllowBlocked: the module is in _blocklisted_modules, which is consulted
	// before the allowlist, so the name is rejected even if a user tries to
	// allowlist it.
	AllowBlocked
	// AllowConditional: accepted only when the owning torch submodule has been
	// imported in the loading process (nested-jagged-tensor and DTensor names).
	// Statically unverifiable, so it is reported at low confidence.
	AllowConditional
)

func (a AllowVerdict) String() string {
	switch a {
	case AllowDefault:
		return "allowed"
	case AllowBlocked:
		return "blocked-module"
	case AllowConditional:
		return "conditional"
	default:
		return "not-allowed"
	}
}

// blockedModules is _blocklisted_modules verbatim. The loader checks this list
// *before* the allowlist, so a name in one of these modules is never loadable even
// through add_safe_globals.
var blockedModules = map[string]bool{
	"sys":   true,
	"os":    true,
	"posix": true,
	"nt":    true,
}

// allowedStatic is the literal dictionary from _get_allowed_globals().
var allowedStatic = map[string]bool{
	"collections.OrderedDict":             true,
	"collections.Counter":                 true,
	"torch.nn.parameter.Parameter":        true,
	"torch.serialization._get_layout":     true,
	"torch.Size":                          true,
	"torch.Tensor":                        true,
	"torch.device":                        true,
	"_codecs.encode":                      true,
	"builtins.bytearray":                  true,
	"builtins.set":                        true,
	"builtins.complex":                    true,
	"torch._tensor._rebuild_from_type_v2": true,
}

// allowedDtypes maps every name from _dtype_to_storage_type_map().keys() and
// _new_dtypes(), plus the uint1..7 / int1..7 wrappers, which the upstream code
// adds with `getattr(torch, f"uint{x}")`.
var allowedDtypes = map[string]bool{
	// _dtype_to_storage_type_map() keys.
	"torch.double":   true,
	"torch.float":    true,
	"torch.half":     true,
	"torch.long":     true,
	"torch.int":      true,
	"torch.int16":    true,
	"torch.int8":     true,
	"torch.uint8":    true,
	"torch.bool":     true,
	"torch.bfloat16": true,
	"torch.cdouble":  true,
	"torch.cfloat":   true,
	"torch.qint8":    true,
	"torch.qint32":   true,
	"torch.quint8":   true,
	"torch.quint4x2": true,
	"torch.quint2x4": true,
	// _new_dtypes().
	"torch.float8_e5m2":     true,
	"torch.float8_e4m3fn":   true,
	"torch.float8_e5m2fnuz": true,
	"torch.float8_e4m3fnuz": true,
	"torch.float8_e8m0fnu":  true,
	"torch.bits8":           true,
	"torch.bits16":          true,
	"torch.bits1x8":         true,
	"torch.bits2x4":         true,
	"torch.bits4x2":         true,
	"torch.complex32":       true,
	"torch.uint16":          true,
	"torch.uint32":          true,
	"torch.uint64":          true,
	// getattr(torch, "uint1".."uint7") and "int1".."int7".
	"torch.uint1": true, "torch.uint2": true, "torch.uint3": true, "torch.uint4": true,
	"torch.uint5": true, "torch.uint6": true, "torch.uint7": true,
	"torch.int1": true, "torch.int2": true, "torch.int3": true, "torch.int4": true,
	"torch.int5": true, "torch.int6": true, "torch.int7": true,
	// Older aliases that resolve to the same dtype objects and appear in
	// checkpoints written by torch 1.x.
	"torch.float32": true, "torch.float64": true,
	"torch.int32": true, "torch.int64": true,
	"torch.complex64": true, "torch.complex128": true,
	"torch.float16": true,
}

// tensorClassNames is the modelled form of torch._tensor_classes. The upstream
// set is built at import time from `torch.Tensor` plus every dtype-specific
// subclass the build registered, so it cannot be enumerated statically. The model
// is the concrete list of classes the upstream set contains on a CPU build, plus
// the family rules in isAllowed.
var tensorClassNames = map[string]bool{
	"torch.Tensor":              true,
	"torch.nn.Parameter":        true,
	"torch.FloatTensor":         true,
	"torch.DoubleTensor":        true,
	"torch.HalfTensor":          true,
	"torch.BFloat16Tensor":      true,
	"torch.ByteTensor":          true,
	"torch.CharTensor":          true,
	"torch.ShortTensor":         true,
	"torch.IntTensor":           true,
	"torch.LongTensor":          true,
	"torch.BoolTensor":          true,
	"torch.cuda.FloatTensor":    true,
	"torch.cuda.DoubleTensor":   true,
	"torch.cuda.HalfTensor":     true,
	"torch.cuda.BFloat16Tensor": true,
	"torch.cuda.ByteTensor":     true,
	"torch.cuda.CharTensor":     true,
	"torch.cuda.ShortTensor":    true,
	"torch.cuda.IntTensor":      true,
	"torch.cuda.LongTensor":     true,
	"torch.cuda.BoolTensor":     true,
}

// storageClassNames is the modelled form of torch._storage_classes keyed the way
// the allowlist keys them: the legacy `<type>Storage` classes first (wrapped in
// torch.serialization.StorageType by the loader), then the two real classes.
var storageClassNames = map[string]bool{
	"torch.storage.UntypedStorage": true,
	"torch.storage.TypedStorage":   true,
	"torch.UntypedStorage":         true,
	"torch.TypedStorage":           true,
	"torch.DoubleStorage":          true,
	"torch.FloatStorage":           true,
	"torch.HalfStorage":            true,
	"torch.LongStorage":            true,
	"torch.IntStorage":             true,
	"torch.ShortStorage":           true,
	"torch.CharStorage":            true,
	"torch.ByteStorage":            true,
	"torch.BoolStorage":            true,
	"torch.BFloat16Storage":        true,
	"torch.ComplexDoubleStorage":   true,
	"torch.ComplexFloatStorage":    true,
	"torch.ComplexHalfStorage":     true,
	"torch.QInt8Storage":           true,
	"torch.QInt32Storage":          true,
	"torch.QUInt8Storage":          true,
	"torch.QUInt4x2Storage":        true,
	"torch.QUInt2x4Storage":        true,
}

// rebuildFunctions is _tensor_rebuild_functions(), exposed by the loader as
// "torch._utils.<__name__>".
var rebuildFunctions = map[string]bool{
	"torch._utils._rebuild_parameter":                     true,
	"torch._utils._rebuild_parameter_with_state":          true,
	"torch._utils._rebuild_qtensor":                       true,
	"torch._utils._rebuild_tensor":                        true,
	"torch._utils._rebuild_tensor_v2":                     true,
	"torch._utils._rebuild_tensor_v3":                     true,
	"torch._utils._rebuild_sparse_tensor":                 true,
	"torch._utils._rebuild_meta_tensor_no_storage":        true,
	"torch._utils._rebuild_nested_tensor":                 true,
	"torch._utils._rebuild_wrapper_subclass":              true,
	"torch._utils._rebuild_device_tensor_from_numpy":      true,
	"torch._utils._rebuild_device_tensor_from_cpu_tensor": true,
}

// quantLayouts is the quantization-layout list from _get_allowed_globals().
var quantLayouts = map[string]bool{
	"torch.per_tensor_affine":                true,
	"torch.per_tensor_symmetric":             true,
	"torch.per_channel_affine":               true,
	"torch.per_channel_symmetric":            true,
	"torch.per_channel_affine_float_qparams": true,
}

// conditionalGlobals are the names the loader accepts only when the owning torch
// submodule is already imported. They are reported at low confidence because the
// scanner cannot see the loading process's import graph.
var conditionalGlobals = map[string]bool{
	"torch.nested._internal.nested_tensor.NestedTensor":  true,
	"torch.nested._internal.nested_tensor._rebuild_njt":  true,
	"torch._dynamo.decorators._DimRange":                 true,
	"torch.distributed.device_mesh.DeviceMesh":           true,
	"torch.distributed.tensor._dtensor_spec.DTensorSpec": true,
	"torch.distributed.tensor._dtensor_spec.TensorMeta":  true,
	"torch.distributed.tensor.DTensor":                   true,
	"torch.distributed.tensor.placement_types.Partial":   true,
	"torch.distributed.tensor.placement_types.Replicate": true,
	"torch.distributed.tensor.placement_types.Shard":     true,
}

// importMapping and nameMapping are torch/_utils.py's IMPORT_MAPPING and
// NAME_MAPPING, which the loader applies while reading a GLOBAL name. A scanner
// that ignores them will mis-resolve a Python-2-era checkpoint's names (the
// common one being `__builtin__` -> `builtins`), which is the direction that
// produces false positives.
var importMapping = map[string]string{
	"__builtin__": "builtins",
	"copy_reg":    "copyreg",
	"Queue":       "queue",
	"repr":        "reprlib",
	"_abcoll":     "collections.abc",
	"UserDict":    "collections",
	"UserList":    "collections",
	"UserString":  "collections",
	"whichdb":     "dbm",
	"StringIO":    "io",
	"cStringIO":   "io",
}

var nameMapping = map[[2]string][2]string{
	{"__builtin__", "xrange"}:        {"builtins", "range"},
	{"__builtin__", "reduce"}:        {"functools", "reduce"},
	{"__builtin__", "intern"}:        {"sys", "intern"},
	{"__builtin__", "unichr"}:        {"builtins", "chr"},
	{"__builtin__", "unicode"}:       {"builtins", "str"},
	{"__builtin__", "long"}:          {"builtins", "int"},
	{"itertools", "izip"}:            {"builtins", "zip"},
	{"itertools", "imap"}:            {"builtins", "map"},
	{"itertools", "ifilter"}:         {"builtins", "filter"},
	{"itertools", "ifilterfalse"}:    {"itertools", "filterfalse"},
	{"itertools", "izip_longest"}:    {"itertools", "zip_longest"},
	{"UserDict", "IterableUserDict"}: {"collections", "UserDict"},
	{"UserList", "UserList"}:         {"collections", "UserList"},
	{"UserString", "UserString"}:     {"collections", "UserString"},
	{"__builtin__", "basestring"}:    {"builtins", "str"},
	{"exceptions", "StandardError"}:  {"builtins", "Exception"},
	{"UserDict", "UserDict"}:         {"collections", "UserDict"},
}

// resolveGlobal applies the loader's name patching and returns the name the
// loader would see, plus whether anything was remapped.
func resolveGlobal(module, name string) (string, string, bool) {
	remapped := false
	if pair, ok := nameMapping[[2]string{module, name}]; ok {
		module, name = pair[0], pair[1]
		remapped = true
	} else if m, ok := importMapping[module]; ok {
		module = m
		remapped = true
	}
	return module, name, remapped
}

// isAllowed evaluates the allowlist for a qualified name. The order of the checks
// is the loader's order: blocked modules first, then the exact dictionary, then
// the derived families.
func isAllowed(module, name string) AllowVerdict {
	if blockedModules[module] {
		return AllowBlocked
	}
	q := module + "." + name
	if allowedStatic[q] || allowedDtypes[q] || tensorClassNames[q] ||
		storageClassNames[q] || rebuildFunctions[q] || quantLayouts[q] {
		return AllowDefault
	}
	if conditionalGlobals[q] {
		return AllowConditional
	}
	// Family rules for the derived sets that cannot be enumerated statically. Each
	// is deliberately narrow: a family rule that is too broad would classify a
	// real gadget as allowlisted.
	if module == "torch" {
		// torch._tensor_classes contains one class per dtype; on a build with
		// extra backends there are more of them, all named <Something>Tensor.
		if strings.HasSuffix(name, "Tensor") {
			return AllowDefault
		}
	}
	if module == "torch" || module == "torch.storage" {
		if strings.HasSuffix(name, "Storage") {
			return AllowDefault
		}
	}
	return AllowNo
}

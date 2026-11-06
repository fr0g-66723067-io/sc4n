"""Validate an ONNX model inside the oracle image.

Reads a JSON argument file (path, mode) so one invocation serves both validity
modes: "checker" runs onnx.checker over the model document, "session" also builds
an onnxruntime.InferenceSession, which is what a loader does with it.

Everything goes through the *path*, never a ModelProto: check_model(ModelProto)
has no model directory, so it resolves an external-data location against the
process CWD and every traversal row would fail for the wrong reason. The C++
checker opens the model's external files itself, which is also what makes the
NUL-truncated location ("w_ext.bin\\0.txt") resolvable to the file it names.

Exit 0 when the model is valid, 1 when it is not (the exception text goes to
stderr so the Go side can put it in the matrix cell).
"""
import json
import sys
import traceback


def main() -> int:
    arg = json.load(open(sys.argv[1]))
    path = arg["path"] if arg["path"].startswith("/") else "/w/" + arg["path"]
    try:
        import onnx

        onnx.checker.check_model(path)
        if arg.get("mode", "checker") == "session":
            import onnxruntime as ort

            # Constructing the session is the loader's own validity check. It is
            # never run: no inputs are fed and no output is read.
            ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        print("ok")
        return 0
    except Exception:  # noqa: BLE001 - the exception text IS the answer
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

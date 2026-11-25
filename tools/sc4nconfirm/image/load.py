#!/usr/bin/env python3
"""Load one artifact the way a user would, and record what happened.

The loader choice is the whole experiment: a `pytorch_model.bin` is loaded by
`torch.load`, a `.joblib` by `joblib.load`, a `.npz`/`.npy` by
`numpy.load(allow_pickle=True)` (a `.npz` member is indexed, because numpy
unpickles an object array only on access), a model directory with an `auto_map`
by importing the modules that map names and then `from_pretrained`, and a
`tokenizer_config.json` by rendering its chat template. Whatever the payload does
happens for real - inside a container with no network and a read-only root, under
strace, which is why running it here is safe in the sense that matters.

Exit status is always 0: the result file is the report, and a load that failed is
a fact about the artifact, not an error in the harness. The one exception is a
result file that cannot be written.
"""

import json
import os
import sys
import traceback

RESULT = {"loader": "", "loaded": False, "error": "", "missingModules": []}

# The loader starts as root only because the entrypoint starts it under the
# root-owned tracer. Nothing artifact-controlled may run with that identity: the
# artifact is chosen by an attacker, and its first instruction is the payload.
PAYLOAD_UID = 65534


def drop_privileges():
    """Become the unprivileged payload identity, or fail closed."""
    os.setgroups([])
    os.setgid(PAYLOAD_UID)
    os.setuid(PAYLOAD_UID)
    if os.getuid() != PAYLOAD_UID or os.geteuid() != PAYLOAD_UID:
        raise RuntimeError("could not drop to uid %d" % PAYLOAD_UID)

# An .npz member above this size is a tensor, not a payload; reading it would
# cost the container's memory and demonstrate nothing. The bound comes from the
# zip metadata, so it is checked before the member is decompressed.
NPZ_MEMBER_CAP = 64 << 20


def auto_map_modules(directory):
    """The local modules a model directory's config.json names in auto_map."""
    try:
        with open(os.path.join(directory, "config.json"), "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return []
    am = cfg.get("auto_map")
    if not isinstance(am, dict):
        return []
    mods = []
    for v in am.values():
        refs = v if isinstance(v, list) else [v]
        for ref in refs:
            if not isinstance(ref, str) or "." not in ref:
                continue
            mod = ref.rsplit(".", 1)[0]
            # A remote reference is owner/repo--module.Class: not a local file.
            if not mod or "/" in mod or "--" in mod or ".." in mod:
                continue
            if mod not in mods:
                mods.append(mod)
    return mods


def chat_template(path):
    """The chat template a tokenizer_config.json carries, or None."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    tmpl = cfg.get("chat_template") or cfg.get("chat_template_jinja")
    if isinstance(tmpl, str):
        return tmpl
    if isinstance(tmpl, list):
        for entry in tmpl:
            if isinstance(entry, dict) and isinstance(entry.get("template"), str):
                return entry["template"]
    return None


def pick(path):
    """Return (loader name, callable that loads it)."""
    low = path.lower()
    if os.path.isdir(path):
        return "AutoModel.from_pretrained", lambda: load_model_dir(path)
    if low.endswith((".pt", ".pth", ".bin", ".ckpt", ".tar", ".model")):
        import torch

        return "torch.load", lambda: torch.load(
            path, map_location="cpu", weights_only=False
        )  # nosec B614 -- the harness loads the artifact on purpose
    if low.endswith((".joblib", ".jl")):
        import joblib

        return "joblib.load", lambda: joblib.load(path)
    if low.endswith((".pkl", ".pickle", ".pcl")):
        import pickle

        def _pickle_load():
            with open(path, "rb") as f:
                return pickle.load(f)  # nosec B301 -- the harness unpickles the artifact on purpose

        return "pickle.load", _pickle_load
    if low.endswith(".npz"):
        import numpy as np

        def _npz_load():
            # np.load alone unpickles nothing: an NpzFile reads a member only
            # when that member is indexed, and an object-dtype member is
            # unpickled at that moment. A loader that stopped at np.load would
            # demonstrate nothing, so every member small enough to be the
            # payload is read.
            with np.load(path, allow_pickle=True) as z:
                sizes = {}
                zipfile = getattr(z, "zip", None)
                if zipfile is not None:
                    sizes = {i.filename: i.file_size for i in zipfile.infolist()}
                for name in z.files:
                    member_size = sizes.get(name, sizes.get(name + ".npy", 0))
                    if member_size > NPZ_MEMBER_CAP:
                        # Weights, not a payload: reading it would only cost the
                        # container's memory.
                        continue
                    _ = z[name]
            return True

        return "numpy.load(allow_pickle=True)", _npz_load
    if low.endswith(".npy"):
        import numpy as np

        # A .npy of object dtype is unpickled by the load itself.
        return "numpy.load(allow_pickle=True)", lambda: np.load(
            path, allow_pickle=True
        )
    if low.endswith(".json"):
        tmpl = chat_template(path)
        if tmpl is not None:
            import jinja2

            def _render():
                env = jinja2.Environment()
                # A bounded render: a template that loops forever is a payload
                # too, and the container timeout is the backstop. Pass sample
                # messages so templates iterating over messages execute their body.
                return env.from_string(tmpl).render(
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant."},
                        {"role": "user", "content": "Hello"},
                    ],
                    add_generation_prompt=True,
                    bos_token="",
                    eos_token="",
                )

            return "jinja2.render(chat_template)", _render
    raise ValueError("no loader for this artifact type")


def load_model_dir(directory):
    """Import the auto_map modules, then load the model with trust_remote_code.

    The import comes first on purpose: it is the thing under test (a module's
    import-time body is attacker code), and from_pretrained can refuse for a
    reason that has nothing to do with the module - a missing model_type, an
    architecture Transformers cannot map - in which case the module body would
    still have run in a real load.
    """
    sys.path.insert(0, directory)
    for mod in auto_map_modules(directory):
        __import__(mod)
    from transformers import AutoModel

    return AutoModel.from_pretrained(directory, trust_remote_code=True)


def main(argv):
    if len(argv) != 3:
        RESULT["error"] = "usage: load.py TARGET RESULT"
        return 1
    target, result_path = argv[1], argv[2]
    try:
        drop_privileges()
        RESULT["uid"] = os.getuid()
        name, fn = pick(target)
        RESULT["loader"] = name
        fn()
        RESULT["loaded"] = True
    except BaseException as e:  # noqa: BLE001 - a payload may raise anything
        RESULT["loaded"] = False
        RESULT["error"] = "%s: %s" % (type(e).__name__, str(e)[:300])
        if not isinstance(e, ModuleNotFoundError):
            # The traceback goes to stderr, which the caller keeps in the
            # scratch directory: it is how a human explains a surprising
            # "loaded: false". A missing module is not a payload failure.
            traceback.print_exc()
        if isinstance(e, ModuleNotFoundError):
            RESULT["missingModules"] = [e.name or "unknown"]
            RESULT["error"] = "ModuleNotFoundError: %s" % (e.name or "")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(RESULT, f, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

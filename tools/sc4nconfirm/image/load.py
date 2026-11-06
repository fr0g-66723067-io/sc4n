#!/usr/bin/env python3
"""Load one artifact the way a user would, and record what happened.

The loader choice is the whole experiment: a `pytorch_model.bin` is loaded by
`torch.load`, a `.joblib` by `joblib.load`, a model directory with an `auto_map`
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
        )
    if low.endswith((".joblib", ".jl")):
        import joblib

        return "joblib.load", lambda: joblib.load(path)
    if low.endswith((".pkl", ".pickle", ".pcl")):
        import pickle

        def _pickle_load():
            with open(path, "rb") as f:
                return pickle.load(f)

        return "pickle.load", _pickle_load
    if low.endswith(".json"):
        tmpl = chat_template(path)
        if tmpl is not None:
            import jinja2

            def _render():
                env = jinja2.Environment()
                # A bounded render: a template that loops forever is a payload
                # too, and the container timeout is the backstop.
                return env.from_string(tmpl).render()

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
        name, fn = pick(target)
        RESULT["loader"] = name
        fn()
        RESULT["loaded"] = True
    except ModuleNotFoundError as e:
        RESULT["loaded"] = False
        RESULT["missingModules"] = [e.name or "unknown"]
        RESULT["error"] = "ModuleNotFoundError: %s" % (e.name or "")
    except BaseException as e:  # noqa: BLE001 - a payload may raise anything
        RESULT["loaded"] = False
        RESULT["error"] = "%s: %s" % (type(e).__name__, str(e)[:300])
        # The traceback goes to stderr, which the caller keeps in the scratch
        # directory: it is how a human explains a surprising "loaded: false".
        traceback.print_exc()
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(RESULT, f, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

// Package repo analyses the files in a scanned tree that execute on install or at
// interpreter start, rather than files inside a model artifact. It is where the
// supply-chain half of the plan lives: a `setup.py` with a custom install hook, a
// `pyproject.toml` naming an arbitrary PEP 517 backend, a `.pth` file that runs
// `import` at every interpreter start, a GitHub workflow that interpolates
// attacker-controlled event data into a shell, and a wheel checked into a model
// repository.
//
// The package exposes AnalyzeFile for a path-based walker and also registers a
// universal layer, so the rules apply when the scan engine scans a file directly.
// The universal layer filters on the artifact's display name before reading any
// bytes, so an unrelated artifact is neither read nor slowed down by this package.
package repo

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The repository-file rule set. Each rule's description states the trigger,
// because "why did this fire" is the only question a reader has about a
// one-line-config finding.

var (
	rulePth = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-PTH",
		Title:      "Path configuration file executes code at interpreter start",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-94"},
		Class:      "repo",
		Description: "A .pth file has a line beginning with `import ` or `exec`. .pth files are not data: " +
			"site.py executes any line that starts with `import` (or `import ` followed by a module with " +
			"a `__main__`-style side effect) at the start of *every* interpreter run in that environment, " +
			"with no import required. A .pth file inside a wheel is therefore code execution on install, " +
			"and the reason a wheel in a model repository is scanned rather than trusted.",
		Refs: []string{
			"https://docs.python.org/3/library/site.html",
			"https://cwe.mitre.org/data/definitions/94.html",
		},
		Tags: []string{"startup", "supply-chain"},
	})

	ruleStart = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-START",
		Title:      "Python 3.15 startup entry point file executes a callable",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-94"},
		Class:      "repo",
		Description: "A file named *.start contains an entry point of the form `pkg.mod:callable`. Python " +
			"3.15+ executes these at interpreter startup, analogous to a .pth file but naming a callable " +
			"directly, so the file is code that runs before the user's own program.",
		Refs: []string{"https://docs.python.org/3.15/whatsnew/3.15.html"},
		Tags: []string{"startup", "supply-chain"},
	})

	ruleSetupHook = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-SETUP-HOOK",
		Title:      "setup.py installs a custom command hook",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "setup.py references cmdclass or defines one of the install/develop/build_py/sdist/" +
			"egg_info/build_ext commands, or runs a shell/exec sink at module scope. A cmdclass entry " +
			"replaces setuptools' own command, so the hook body runs during `pip install` with the " +
			"installer's privileges; sc4n reports the trigger it saw. Ordinary setup.py files that only " +
			"call setup() with metadata do not fire.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"install-time", "supply-chain"},
	})

	ruleBuildBackend = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-BUILD-BACKEND",
		Title:      "pyproject.toml names a build backend outside the known-good set",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "The [build-system] build-backend is not one of the common, well-understood backends " +
			"(setuptools.build_meta[:__legacy__], hatchling.build, flit_core.buildapi, " +
			"poetry.core.masonry.api, maturin, scikit_build_core.build). PEP 517 imports and runs the " +
			"named backend at build time, so an arbitrary backend name is code execution during build, " +
			"before any package code is reviewed.",
		Refs: []string{
			"https://peps.python.org/pep-0517/",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
		Tags: []string{"build-time", "supply-chain"},
	})

	ruleRepoTroncated = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-TRUNCATED",
		Title:      "Repository file truncated before analysis",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-693"},
		Class:      "repo",
		Description: "A repository file larger than the analysis cap was analysed only on its prefix. " +
			"The tail was not examined, and a .pth, setup.py or workflow sink placed after the cap is " +
			"therefore invisible; the finding fails a high gate rather than presenting the prefix as the " +
			"whole file.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/693.html"},
		Tags: []string{"supply-chain", "truncation"},
	})

	ruleBackendPath = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-BACKEND-PATH",
		Title:      "PEP 517 backend-path shadows the allowlisted build backend",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-427"},
		Class:      "repo",
		Description: "A pyproject.toml [build-system] sets backend-path. PEP 517 puts those directories " +
			"ahead of the installed backend on sys.path, so repository code can shadow a module the " +
			"allowlisted backend imports. The backend name can be known-good while the code that runs is " +
			"the repository's.",
		Refs: []string{"https://peps.python.org/pep-0517/#in-tree-build-backends"},
		Tags: []string{"build-time", "supply-chain"},
	})

	ruleSiteCustomize = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-SITE-CUSTOMIZE",
		Title:      "sitecustomize/usercustomize module runs at interpreter start",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "A sitecustomize.py or usercustomize.py is present. Python imports sitecustomize " +
			"(and usercustomize) automatically at startup, so whatever it contains runs in every " +
			"interpreter in that environment without being imported by anything.",
		Refs: []string{"https://docs.python.org/3/library/site.html"},
		Tags: []string{"startup", "supply-chain"},
	})

	rulePycOrphan = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-PYC-ORPHAN",
		Title:      "Compiled .pyc has no .py source beside it",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "A .pyc file with no sibling .py exists on disk. There is no source to lint, so " +
			"whatever the bytecode does was not analysed; this is informational and does not by itself " +
			"mean the bytecode is malicious, but a repository that ships only .pyc has nothing to review.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"bytecode"},
	})

	ruleWorkflowPRT = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-WORKFLOW-PRT",
		Title:      "GitHub workflow interpolates event data into a run step",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-94"},
		Class:      "repo",
		Description: "A .github/workflows file combines pull_request_target with a `run:` step that " +
			"interpolates `${{ github.event.* }}`. pull_request_target runs with the base repository's " +
			"secrets, and interpolating attacker-controlled event fields (a PR title, branch name or " +
			"body) into a shell command is command injection into that privileged context. The match is " +
			"textual (there is no YAML library linked), so it reports the co-occurrence rather than " +
			"proving the interpolation reaches a shell.",
		Refs: []string{"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"},
		Tags: []string{"ci", "supply-chain"},
	})

	ruleWheelInModel = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-WHEEL-IN-MODEL",
		Title:      "Python package archive found in the scanned tree",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "A .whl, .tar.gz or .tgz package archive sits in the scanned tree. A package " +
			"archive installs code: it can ship a setup.py build hook, a .pth file or a .pyc. Its " +
			"members are scanned separately as an archive, so this finding is the pointer to that scan, " +
			"not a substitute for it — and the pointer is name-only, because telling an sdist from a " +
			"dataset tarball needs the archive's members (a dataset.tar.gz and a diffsynth-1.0.tar.gz " +
			"are the same bytes to a name test). Medium severity and low confidence for that reason: the " +
			"same calibration as the name-driven Dockerfile and app.py pointers, where the content rules " +
			"elsewhere in this package (a .pth line, a setup.py hook, a sitecustomize module) are the " +
			"high and critical ones.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"supply-chain", "install-time"},
	})

	ruleDockerfile = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-DOCKERFILE",
		Title:      "Dockerfile present in the scanned tree",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "A Dockerfile is present. A Dockerfile is executed when its image is built and it can " +
			"fetch and run arbitrary code (RUN, ADD of a remote URL, base-image scripts). sc4n does not " +
			"parse Dockerfiles; this finding exists so a container definition in a model repository is " +
			"reviewed rather than overlooked.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"container", "build-time"},
	})

	ruleSpaceApp = report.DefineRule(report.Rule{
		ID:         "SC4N-REPO-SPACE-APP",
		Title:      "app.py present in the scanned tree",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-506"},
		Class:      "repo",
		Description: "An app.py is present. app.py is the Gradio entry point a Hugging Face Space runs on " +
			"container start, and the file a Space's build executes without the user opening it. sc4n does " +
			"not parse the file here; the Python analyser covers its contents. This finding marks the " +
			"entry point so a reviewer knows the tree is runnable rather than a static model directory.",
		Refs: []string{"https://huggingface.co/docs/hub/spaces-overview"},
		Tags: []string{"space", "execution"},
	})
)

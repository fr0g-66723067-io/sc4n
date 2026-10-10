package formats

import (
	// Python source and notebook analysis, plus the repository-file rules (the
	// .pth/.start/setup.py/pyproject.toml/workflow/wheel universal layer that
	// internal/repo registers).
	_ "github.com/fr0g-66723067-io/sc4n/internal/pysrc"
	_ "github.com/fr0g-66723067-io/sc4n/internal/repo"
)

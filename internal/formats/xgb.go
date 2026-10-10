package formats

import (
	// XGBoost/LightGBM/CatBoost family: the UBJSON `.ubj` dialect; the
	// legacy `.model`/`.deprecated` and `.pkl` shapes are pickles and are handled
	// by the pickle engine.
	_ "github.com/fr0g-66723067-io/sc4n/internal/xgb"
)

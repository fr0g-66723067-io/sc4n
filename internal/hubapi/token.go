package hubapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func cleanToken(raw string) (string, error) {
	tok := strings.TrimSpace(raw)
	if strings.ContainsAny(tok, "\r\n") {
		return "", errors.New("hubapi: token contains CR or LF")
	}
	return tok, nil
}

// Token resolves the Hub bearer token, in the order the Hub's own client uses:
// the explicit file when one is given, then HF_TOKEN, then
// HUGGING_FACE_HUB_TOKEN, then $HF_HOME/token (default ~/.cache/huggingface/token).
//
// Every step may legitimately find nothing: an anonymous campaign is allowed and
// simply sees more gated downloads, which the campaign reports instead of hiding.
func Token(explicitFile string) (string, error) {
	if explicitFile != "" {
		b, err := os.ReadFile(explicitFile)
		if err != nil {
			return "", fmt.Errorf("hubapi: token file: %w", err)
		}
		tok, err := cleanToken(string(b))
		if err != nil {
			return "", err
		}
		if tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("hubapi: token file %s is empty", explicitFile)
	}
	for _, k := range []string{"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"} {
		if v := os.Getenv(k); strings.TrimSpace(v) != "" {
			return cleanToken(v)
		}
	}
	home := os.Getenv("HF_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", nil
		}
		home = filepath.Join(h, ".cache", "huggingface")
	}
	b, err := os.ReadFile(filepath.Join(home, "token"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("hubapi: token file: %w", err)
	}
	return cleanToken(string(b))
}

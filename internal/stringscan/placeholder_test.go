package stringscan

import "testing"

// TestPlaceholderAssignmentsAreNotSecrets pins the filter that keeps
// SC4N-STRING-SECRET-VALUE about secret material. The literal table cannot see
// what follows `api_key=`, so without the filter a local-server example in a README
// (`api_key="EMPTY"`, `api_key="none"`, `api_key='your-api-key'`) is a high
// finding: measured on the Hugging Face corpus, widening the assignment shapes
// added 15 such findings and every one of them was documentation.
func TestPlaceholderAssignmentsAreNotSecrets(t *testing.T) {
	cases := []struct {
		text string
		want bool // want a secret-assignment hit
	}{
		{`api_key="EMPTY"`, false},
		{`api_key="none"`, false},
		{`api_key="not-needed"`, false},
		{`api_key='your-api-key'`, false},
		{`api_key=<your-key>`, false},
		{`api_key=${MY_TOKEN}`, false},
		{`password=password`, false},
		{`passwd=`, false},
		{`secret=xxx`, false},
		{`secret="redacted"`, false},
		{`token=12345678`, false},
		{`password=hunter2`, true},
		{`client_secret=a1b2c3d4e5f60718293a4b5c6d7e8f90`, true},
		{`AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, true},
	}
	for _, tc := range cases {
		got := false
		for _, h := range scan([]byte(tc.text + "\n")) {
			if h.Rule == ruleSecretValue && h.Extra["kind"] == "secret-assignment" {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("scan(%q): secret-assignment reported = %v, want %v", tc.text, got, tc.want)
		}
	}
}

// TestPlaceholderFilterDoesNotHideTokenShapes is the control on the same path:
// the filter is scoped to assignment shapes, so a vendor-shaped value is reported
// wherever it appears — including inside a document whose other assignments are
// placeholders.
func TestPlaceholderFilterDoesNotHideTokenShapes(t *testing.T) {
	var got []string
	for _, h := range scan([]byte("api_key=\"EMPTY\"\ntoken=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")) {
		if h.Rule == ruleSecretValue {
			got = append(got, h.Extra["kind"]+"/"+h.Extra["shape"])
		}
	}
	if len(got) != 1 || got[0] != "secret-token/ghp_" {
		t.Fatalf("want exactly the ghp_ token shape, got %v", got)
	}
}

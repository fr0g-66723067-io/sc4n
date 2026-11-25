package main

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSeedKeyDistinguishesSameBasename(t *testing.T) {
	a := seedKey("/seeds/repo-a/model.onnx")
	b := seedKey("/seeds/repo-b/model.onnx")
	if a == b {
		t.Fatalf("seedKey collided for different parent paths: %q", a)
	}
	if a != seedKey("/seeds/repo-a/./model.onnx") {
		t.Fatalf("seedKey is not deterministic on cleaned paths: %q", a)
	}
}

func TestDockerOracleArgsAndJSON(t *testing.T) {
	args := dockerOracleArgs("/tmp/d", "/tmp/py", "sc4n-oracle:1")
	for _, want := range []string{"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "1g", "--pids-limit", "64"} {
		if !slices.Contains(args, want) {
			t.Errorf("dockerOracleArgs missing %q: %v", want, args)
		}
	}
	raw, err := json.Marshal(oracleCheckReq{Path: `evil"name\x.onnx`, Mode: "session"})
	if err != nil {
		t.Fatal(err)
	}
	var got oracleCheckReq
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Path != `evil"name\x.onnx` || got.Mode != "session" {
		t.Fatalf("round-trip = %+v", got)
	}
}

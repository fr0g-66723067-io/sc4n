package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

var (
	testRuleCritical = DefineRule(Rule{
		ID: "SC4N-TEST-CRITICAL", Title: "test critical", Severity: SeverityCritical,
		Confidence: ConfidenceHigh, CWE: []string{"CWE-502"}, Class: "test",
		Description: "test rule",
	})
	testRuleInfo = DefineRule(Rule{
		ID: "SC4N-TEST-INFO", Title: "test info", Severity: SeverityInfo,
		Confidence: ConfidenceLow, Class: "test", Description: "test rule",
	})
)

func TestFindingsSortIsDeterministic(t *testing.T) {
	c := NewCollector(0)
	sinkB := c.For("b.pkl")
	sinkA := c.For("a.pkl")
	sinkB.Emit(testRuleCritical, 10, "second")
	sinkA.Emit(testRuleInfo, 5, "first")
	sinkB.Emit(testRuleInfo, 10, "third")
	sinkA.EmitAt(testRuleInfo, 3, 7, "line-based")

	got := c.Findings()
	want := []struct {
		artifact string
		rule     string
	}{
		{"a.pkl", "SC4N-TEST-INFO"},
		{"a.pkl", "SC4N-TEST-INFO"},
		{"b.pkl", "SC4N-TEST-CRITICAL"},
		{"b.pkl", "SC4N-TEST-INFO"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Artifact != w.artifact || got[i].RuleID != w.rule {
			t.Fatalf("finding %d = %s/%s, want %s/%s", i, got[i].Artifact, got[i].RuleID, w.artifact, w.rule)
		}
	}
	// The line-based finding was emitted with offset 0, so it sorts before the
	// offset-5 one inside the same artifact.
	if got[0].Line == nil || got[1].Line != nil {
		t.Fatal("offset and line findings did not order as documented")
	}
}

func TestCollectorCapCountsDropped(t *testing.T) {
	c := NewCollector(2)
	s := c.For("x")
	for i := range 5 {
		s.Emit(testRuleInfo, int64(i), "e")
	}
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want 2", c.Len())
	}
	if c.Dropped() != 3 {
		t.Fatalf("Dropped = %d, want 3", c.Dropped())
	}
}

func TestMaxSeverityAndCounts(t *testing.T) {
	c := NewCollector(0)
	s := c.For("x")
	s.Emit(testRuleInfo, 0, "a")
	s.Emit(testRuleCritical, 1, "b")
	if c.MaxSeverity() != SeverityCritical {
		t.Fatalf("MaxSeverity = %s", c.MaxSeverity())
	}
	counts := c.CountBySeverity()
	if counts[SeverityInfo] != 1 || counts[SeverityCritical] != 1 {
		t.Fatalf("CountBySeverity = %v", counts)
	}
}

func TestSuppressUsesFingerprint(t *testing.T) {
	c := NewCollector(0)
	s := c.For("x")
	s.Emit(testRuleInfo, 0, "keep")
	s.Emit(testRuleInfo, 1, "drop")
	fp := map[string]bool{Fingerprint(c.Findings()[1]): true}
	if n := c.Suppress(fp); n != 1 {
		t.Fatalf("Suppress removed %d, want 1", n)
	}
	left := c.Findings()
	if len(left) != 1 || left[0].Evidence != "keep" {
		t.Fatalf("after suppress: %+v", left)
	}
}

// TestFingerprintIgnoresOffset pins the baseline contract: inserting bytes earlier
// in a file shifts every later offset, and a fingerprint that included the offset
// would un-suppress the whole baseline on an unrelated edit.
func TestFingerprintIgnoresOffset(t *testing.T) {
	a := Finding{RuleID: "R", Artifact: "p", Offset: 1, Evidence: "payload"}
	b := Finding{RuleID: "R", Artifact: "p", Offset: 999, Evidence: "payload"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("Fingerprint depends on the offset")
	}
	c := Finding{RuleID: "R", Artifact: "p", Offset: 1, Evidence: "payloae"}
	if Fingerprint(a) == Fingerprint(c) {
		t.Fatal("Fingerprint does not depend on the evidence")
	}
}

func TestJSONOutputIsDeterministicAndComplete(t *testing.T) {
	build := func() *Report {
		c := NewCollector(0)
		s := c.For("m.pkl")
		s.EmitExtra(testRuleCritical, 42, "os.system", map[string]string{"global": "os.system"})
		s.EmitAt(testRuleInfo, 3, 1, "note")
		return Build(
			Tool{Name: "sc4n", Version: "test"},
			"",
			[]ArtifactSummary{{Path: "m.pkl", Size: 100, SHA256: "abc", Format: "pickle"}},
			c,
			Limits{MaxDepth: 4, MaxFindings: 10},
			nil,
			0,
		)
	}
	var a, b bytes.Buffer
	if err := build().WriteJSON(&a); err != nil {
		t.Fatal(err)
	}
	if err := build().WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatalf("two runs differ:\n%s\n%s", a.String(), b.String())
	}

	// The JSON must be machine-checkable without a schema: assert the fields the
	// documented schema promises.
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Summary       struct {
			Findings    int    `json:"findings"`
			MaxSeverity string `json:"maxSeverity"`
		} `json:"summary"`
		Findings []struct {
			RuleID     string `json:"ruleId"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			CWE        []string
			Extra      map[string]string `json:"extra"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(a.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1" || doc.Summary.Findings != 2 || doc.Summary.MaxSeverity != "critical" {
		t.Fatalf("summary = %+v", doc.Summary)
	}
	// Offset order first: the line-based finding sits at offset 0.
	if doc.Findings[0].RuleID != "SC4N-TEST-INFO" || doc.Findings[0].Severity != "info" {
		t.Fatalf("first finding = %+v", doc.Findings[0])
	}
	if doc.Findings[0].Confidence != "low" {
		t.Fatalf("confidence not rendered: %+v", doc.Findings[0])
	}
	if doc.Findings[1].RuleID != "SC4N-TEST-CRITICAL" || doc.Findings[1].Severity != "critical" {
		t.Fatalf("second finding = %+v", doc.Findings[1])
	}
	if doc.Findings[1].Extra["global"] != "os.system" {
		t.Fatalf("extra lost: %+v", doc.Findings[1].Extra)
	}
}

func TestCollectorIsConcurrencySafe(t *testing.T) {
	c := NewCollector(0)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := c.For("x")
			for i := range 100 {
				s.Emit(testRuleInfo, int64(w*100+i), "e")
			}
		}()
	}
	wg.Wait()
	if c.Len() != 800 {
		t.Fatalf("Len = %d, want 800", c.Len())
	}
}

func TestSummaryLineReportsSuppressedAndDropped(t *testing.T) {
	c := NewCollector(1)
	s := c.For("x")
	s.Emit(testRuleInfo, 0, "a")
	s.Emit(testRuleInfo, 1, "b")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, c, Limits{}, nil, 7)
	line := rep.SummaryLine()
	for _, want := range []string{"suppressed: 7", "dropped: 1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("SummaryLine() = %q, missing %q", line, want)
		}
	}
}

func TestSeverityParsingAndBands(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		sev, err := ParseSeverity(s)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", s, err)
		}
		if sev.String() != s {
			t.Fatalf("round trip %q -> %s", s, sev)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("ParseSeverity accepted an unknown name")
	}
	if SeverityBand(SeverityCritical) != "9.5" || SeverityBand(SeverityHigh) != "8.0" ||
		SeverityBand(SeverityMedium) != "5.5" || SeverityBand(SeverityLow) != "3.0" ||
		SeverityBand(SeverityInfo) != "0.0" {
		t.Fatal("security-severity bands do not match GitHub's documented thresholds")
	}
	if SARIFLevel(SeverityHigh) != "error" || SARIFLevel(SeverityMedium) != "warning" || SARIFLevel(SeverityLow) != "note" {
		t.Fatal("SARIF level mapping is wrong")
	}
}

// TestSARIFShape is the gate from the plan's verification list: the payload must be
// SARIF 2.1.0 with one run, every ruleId resolvable in tool.driver.rules, at least
// one location per result and a security-severity property.
func TestSARIFShape(t *testing.T) {
	c := NewCollector(0)
	s := c.For("dir/m.pkl")
	s.Emit(testRuleCritical, 5, "os.system('id')")
	s.EmitAt(testRuleInfo, 2, 3, "note")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", []ArtifactSummary{{Path: "dir/m.pkl", Format: "pickle"}}, c, Limits{}, nil, 0)

	var buf bytes.Buffer
	if err := rep.WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
							Tags             []string
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine  int   `json:"startLine"`
							ByteOffset int64 `json:"byteOffset"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          struct {
					SecuritySeverity string `json:"security-severity"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	known := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		known[r.ID] = true
		if r.Properties.SecuritySeverity == "" {
			t.Fatalf("rule %s has no security-severity", r.ID)
		}
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	for _, res := range run.Results {
		if !known[res.RuleID] {
			t.Fatalf("result ruleId %s missing from tool.driver.rules", res.RuleID)
		}
		if len(res.Locations) == 0 {
			t.Fatalf("result %s has no locations", res.RuleID)
		}
		if res.Locations[0].PhysicalLocation.Region.StartLine < 1 {
			t.Fatal("region.startLine must be >= 1")
		}
		if res.Properties.SecuritySeverity == "" {
			t.Fatalf("result %s has no security-severity property", res.RuleID)
		}
		if res.PartialFingerprints["sc4n/v1"] == "" {
			t.Fatalf("result %s has no partial fingerprint", res.RuleID)
		}
	}
	levels := map[string]string{}
	for _, res := range run.Results {
		levels[res.RuleID] = res.Level
	}
	if levels["SC4N-TEST-CRITICAL"] != "error" || levels["SC4N-TEST-INFO"] != "note" {
		t.Fatalf("level mapping = %v", levels)
	}
}

func TestCycloneDXIsWellFormedAndDeterministic(t *testing.T) {
	build := func() *Report {
		c := NewCollector(0)
		c.For("m.keras").Emit(testRuleCritical, 3, "class_name Lambda")
		return Build(Tool{Name: "sc4n", Version: "t"}, "",
			[]ArtifactSummary{{Path: "m.keras", Size: 9, SHA256: "ff", Format: "keras"}}, c, Limits{}, nil, 0)
	}
	var a, b bytes.Buffer
	if err := build().WriteCycloneDX(&a); err != nil {
		t.Fatal(err)
	}
	if err := build().WriteCycloneDX(&b); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("CycloneDX output is not deterministic")
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Serial      string `json:"serialNumber"`
		Components  []struct {
			Type   string `json:"type"`
			BOMRef string `json:"bom-ref"`
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
			Ratings []struct {
				Severity string `json:"severity"`
			} `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(a.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Fatalf("bom header = %s/%s", doc.BOMFormat, doc.SpecVersion)
	}
	if !strings.HasPrefix(doc.Serial, "urn:uuid:") {
		t.Fatalf("serialNumber = %q", doc.Serial)
	}
	if len(doc.Components) != 1 || doc.Components[0].Type != "machine-learning-model" {
		t.Fatalf("components = %+v", doc.Components)
	}
	if doc.Components[0].Hashes[0].Alg != "SHA-256" {
		t.Fatal("component hash algorithm is not SHA-256")
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Affects[0].Ref != doc.Components[0].BOMRef {
		t.Fatal("vulnerability does not reference the scanned component")
	}
	if doc.Vulnerabilities[0].Ratings[0].Severity != "critical" {
		t.Fatalf("severity = %q", doc.Vulnerabilities[0].Ratings[0].Severity)
	}
}

func TestRuleRegistryRejectsMalformed(t *testing.T) {
	for name, r := range map[string]Rule{
		"empty id":     {ID: "NOPE", Title: "t", Class: "c", Description: "d"},
		"no title":     {ID: "SC4N-TEST-X1", Class: "c", Description: "d"},
		"no class":     {ID: "SC4N-TEST-X2", Title: "t", Description: "d"},
		"no desc":      {ID: "SC4N-TEST-X3", Title: "t", Class: "c"},
		"duplicate id": {ID: testRuleInfo.ID, Title: "t", Class: "c", Description: "d"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("DefineRule accepted a malformed rule")
				}
			}()
			DefineRule(r)
		})
	}
}

func TestRulesAreSortedByID(t *testing.T) {
	rs := Rules()
	for i := 1; i < len(rs); i++ {
		if rs[i-1].ID >= rs[i].ID {
			t.Fatalf("Rules() not sorted: %s then %s", rs[i-1].ID, rs[i].ID)
		}
	}
	if _, ok := RuleByID(testRuleInfo.ID); !ok {
		t.Fatal("RuleByID did not find a registered rule")
	}
}

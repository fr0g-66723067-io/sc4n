package report

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
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
	testRuleMedium = DefineRule(Rule{
		ID: "SC4N-TEST-MEDIUM", Title: "test medium", Severity: SeverityMedium,
		Confidence: ConfidenceMedium, Class: "test", Description: "test rule",
	})
	testRuleHigh = DefineRule(Rule{
		ID: "SC4N-TEST-HIGH", Title: "test high", Severity: SeverityHigh,
		Confidence: ConfidenceHigh, Class: "test", Description: "test rule",
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

// capFixture is the mixed-severity set the cap tests share: two medium findings
// in one artifact, and a critical, two highs and an info in another.
func capFixture() []Finding {
	return []Finding{
		{RuleID: testRuleMedium.ID, Artifact: "a.txt", Offset: 4, Severity: SeverityMedium, Evidence: "m1"},
		{RuleID: testRuleMedium.ID, Artifact: "a.txt", Offset: 31, Severity: SeverityMedium, Evidence: "m2"},
		{RuleID: testRuleCritical.ID, Artifact: "b.pkl", Offset: 2, Severity: SeverityCritical, Evidence: "c"},
		{RuleID: testRuleHigh.ID, Artifact: "b.pkl", Offset: 2, Severity: SeverityHigh, Evidence: "h1"},
		{RuleID: testRuleInfo.ID, Artifact: "b.pkl", Offset: 2, Severity: SeverityInfo, Evidence: "i"},
		{RuleID: testRuleHigh.ID, Artifact: "b.pkl", Offset: 30, Severity: SeverityHigh, Evidence: "h2"},
	}
}

// capWanted is the three findings a cap of three must keep from capFixture.
func capWanted() map[string]bool {
	return map[string]bool{
		testRuleCritical.ID + "|b.pkl|2": true,
		testRuleHigh.ID + "|b.pkl|2":     true,
		testRuleHigh.ID + "|b.pkl|30":    true,
	}
}

func findingKey(f Finding) string {
	return f.RuleID + "|" + f.Artifact + "|" + strconv.FormatInt(f.Offset, 10)
}

// TestFindingCapKeepsTheMostSevere pins the property that makes "exit 0" mean
// "nothing at or above -fail-on was hidden": the cap may only drop a finding in
// favour of one that is at least as severe, and the surviving set must not depend
// on the order the workers finished in.
func TestFindingCapKeepsTheMostSevere(t *testing.T) {
	in := capFixture()
	want := capWanted()
	// Three arrival orders: forward, low-severity-first (which is what let a
	// flood of medium findings evict the critical one), and reversed.
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {4, 0, 1, 3, 5, 2}, {5, 4, 3, 2, 1, 0}} {
		c := NewCollector(3)
		for _, i := range order {
			c.Add(in[i])
		}
		got := c.Findings()
		if len(got) != 3 {
			t.Fatalf("order %v: kept %d, want 3", order, len(got))
		}
		for _, g := range got {
			if !want[findingKey(g)] {
				t.Errorf("order %v: kept %s, want only the critical and the two highs", order, findingKey(g))
			}
		}
		if c.Dropped() != 3 {
			t.Errorf("order %v: dropped %d, want 3", order, c.Dropped())
		}
	}
}

// TestPostSuppressionCapKeepsTheMostSevere pins the same property for the Cap
// path, which a baseline run uses: the scan runs uncapped and the cap is applied
// after suppression, so it must select by value rather than by emission order.
func TestPostSuppressionCapKeepsTheMostSevere(t *testing.T) {
	in := capFixture()
	want := capWanted()
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {4, 0, 1, 3, 5, 2}, {5, 4, 3, 2, 1, 0}} {
		c := NewCollector(0)
		for _, i := range order {
			c.Add(in[i])
		}
		if n := c.Cap(3); n != 3 {
			t.Fatalf("order %v: Cap discarded %d, want 3", order, n)
		}
		got := c.Findings()
		if len(got) != 3 {
			t.Fatalf("order %v: kept %d, want 3", order, len(got))
		}
		for _, g := range got {
			if !want[findingKey(g)] {
				t.Errorf("order %v: kept %s, want only the critical and the two highs", order, findingKey(g))
			}
		}
	}
}

// TestFindingCapIsOrderIndependent checks the stronger form: a shuffled arrival
// order and a sorted one produce byte-identical output, which is what the
// determinism gate asks of a capped parallel run.
func TestFindingCapIsOrderIndependent(t *testing.T) {
	in := capFixture()
	forward := NewCollector(4)
	for _, f := range in {
		forward.Add(f)
	}
	backward := NewCollector(4)
	for i := len(in) - 1; i >= 0; i-- {
		backward.Add(in[i])
	}
	a, err := json.Marshal(forward.Findings())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(backward.Findings())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("capped output depends on arrival order:\n%s\n%s", a, b)
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
		// GitHub code scanning de-duplicates on primaryLocationLineHash, so that
		// is the key that must carry a value.
		if res.PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Fatalf("result %s has no primaryLocationLineHash fingerprint", res.RuleID)
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

// TestSARIFOccurrenceCountDistinguishesIdenticalEvidence is the regression for a
// constant occurrence count. Fingerprint excludes the byte offset, so two findings
// of one rule with identical evidence in one file share it; emitting "1:" for both
// made primaryLocationLineHash byte-identical, and that is the value GitHub code
// scanning de-duplicates on, so the second alert was merged into the first. The
// fingerprint itself must not change: it is the baseline identity.
func TestSARIFOccurrenceCountDistinguishesIdenticalEvidence(t *testing.T) {
	c := NewCollector(0)
	s := c.For("dup.txt")
	s.Emit(testRuleMedium, 10, "same evidence")
	s.Emit(testRuleMedium, 49, "same evidence")
	s.Emit(testRuleMedium, 80, "different evidence")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, c, Limits{}, nil, 0)

	var buf bytes.Buffer
	if err := rep.WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	seen := map[string]bool{}
	for _, res := range results {
		fp := res.PartialFingerprints["primaryLocationLineHash"]
		if seen[fp] {
			t.Fatalf("two results share the fingerprint value %q, so GitHub would merge them", fp)
		}
		seen[fp] = true
	}
	// The two identical-evidence findings differ only by their occurrence count,
	// and both keep the same fingerprint prefix (the baseline identity).
	if !strings.HasSuffix(results[0].PartialFingerprints["primaryLocationLineHash"], ":1") ||
		!strings.HasSuffix(results[1].PartialFingerprints["primaryLocationLineHash"], ":2") {
		t.Fatalf("occurrence counts = %q, %q",
			results[0].PartialFingerprints["primaryLocationLineHash"],
			results[1].PartialFingerprints["primaryLocationLineHash"])
	}
	base := strings.TrimSuffix(results[0].PartialFingerprints["primaryLocationLineHash"], ":1")
	if base != Fingerprint(c.Findings()[0]) {
		t.Fatalf("fingerprint prefix %q is not the baseline identity %q", base, Fingerprint(c.Findings()[0]))
	}
}

func TestCycloneDXIsWellFormedAndDeterministic(t *testing.T) {
	build := func() *Report {
		c := NewCollector(0)
		c.For("m.keras").Emit(testRuleCritical, 3, "class_name Lambda")
		return Build(Tool{Name: "sc4n", Version: "t"}, "",
			[]ArtifactSummary{{Path: "m.keras", Size: 9, SHA256: "ff", SHA256Scope: "full", Format: "keras"}}, c, Limits{}, nil, 0)
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

// TestCycloneDXStatesSuppressionAndDrops is the regression for the one encoder
// that could state neither: a baselined BOM whose vulnerabilities are simply
// absent is indistinguishable from a clean scan, and CycloneDX had no
// metadata.properties at all.
func TestCycloneDXStatesSuppressionAndDrops(t *testing.T) {
	decode := func(t *testing.T, buf *bytes.Buffer) map[string]string {
		t.Helper()
		var doc struct {
			Metadata struct {
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, p := range doc.Metadata.Properties {
			got[p.Name] = p.Value
		}
		return got
	}

	// One finding kept, one dropped by the cap, three suppressed by a baseline.
	c := NewCollector(1)
	s := c.For("x")
	s.Emit(testRuleInfo, 0, "a")
	s.Emit(testRuleInfo, 1, "b")
	var buf bytes.Buffer
	if err := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, c, Limits{}, nil, 3).WriteCycloneDX(&buf); err != nil {
		t.Fatal(err)
	}
	got := decode(t, &buf)
	if got["sc4n:suppressed"] != "3" {
		t.Fatalf("sc4n:suppressed = %q, want 3 (properties %v)", got["sc4n:suppressed"], got)
	}
	if got["sc4n:dropped"] != "1" {
		t.Fatalf("sc4n:dropped = %q, want 1 (properties %v)", got["sc4n:dropped"], got)
	}

	// Both are stated even when zero, so a reader can tell "nothing was
	// suppressed" from "this encoder does not say".
	c2 := NewCollector(0)
	c2.For("x").Emit(testRuleInfo, 0, "a")
	var buf2 bytes.Buffer
	if err := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, c2, Limits{}, nil, 0).WriteCycloneDX(&buf2); err != nil {
		t.Fatal(err)
	}
	got = decode(t, &buf2)
	if got["sc4n:suppressed"] != "0" || got["sc4n:dropped"] != "0" {
		t.Fatalf("zero suppression facts are not stated: %v", got)
	}
}

// TestCycloneDXHashScopeIsNotAssumed: a CycloneDX hash is a claim about the whole
// component, so only a digest whose scope says "full" may be published as one. An
// absent scope means the producer did not say, and a whole-file claim must not be
// inferred from silence.
func TestCycloneDXHashScopeIsNotAssumed(t *testing.T) {
	c := NewCollector(0)
	c.For("m.keras").Emit(testRuleCritical, 3, "class_name Lambda")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
		[]ArtifactSummary{{Path: "m.keras", Size: 9, SHA256: "ff", Format: "keras"}}, c, Limits{}, nil, 0)
	var buf bytes.Buffer
	if err := rep.WriteCycloneDX(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			Hashes []struct {
				Alg string `json:"alg"`
			} `json:"hashes"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("components = %d", len(doc.Components))
	}
	if len(doc.Components[0].Hashes) != 0 {
		t.Fatalf("an unscoped digest was published as a component hash: %+v", doc.Components[0].Hashes)
	}
	got := map[string]string{}
	for _, p := range doc.Components[0].Properties {
		got[p.Name] = p.Value
	}
	if got["sc4n:sha256"] != "ff" {
		t.Fatalf("digest not recorded as a property: %+v", got)
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

// TestCycloneDXDoesNotClaimAPrefixDigestAsAFileHash is the CycloneDX half of the
// sha256Scope rule: a CycloneDX `hashes` entry is a claim about the whole
// component, so an artifact whose digest only covered a prefix must not appear
// there — it is published as properties that carry the scope instead.
func TestCycloneDXDoesNotClaimAPrefixDigestAsAFileHash(t *testing.T) {
	c := NewCollector(0)
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", []ArtifactSummary{
		{Path: "big.safetensors", Size: 1 << 40, SHA256: "aaaa", SHA256Scope: "prefix:268435456", Format: "safetensors"},
		{Path: "small.pkl", Size: 10, SHA256: "bbbb", SHA256Scope: "full", Format: "pickle"},
	}, c, Limits{}, nil, 0)

	var buf bytes.Buffer
	if err := rep.WriteCycloneDX(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			Name   string `json:"name"`
			Hashes []struct {
				Content string `json:"content"`
			} `json:"hashes"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CycloneDX output is not valid JSON: %v", err)
	}
	byName := map[string]int{}
	for i, comp := range doc.Components {
		byName[comp.Name] = i
	}
	big := doc.Components[byName["big.safetensors"]]
	if len(big.Hashes) != 0 {
		t.Fatalf("a prefix digest was published as a component hash: %+v", big.Hashes)
	}
	var scope string
	for _, p := range big.Properties {
		if p.Name == "sc4n:sha256Scope" {
			scope = p.Value
		}
	}
	if scope != "prefix:268435456" {
		t.Fatalf("the prefix scope is not recorded as a property: %+v", big.Properties)
	}
	small := doc.Components[byName["small.pkl"]]
	if len(small.Hashes) != 1 || small.Hashes[0].Content != "bbbb" {
		t.Fatalf("a full digest must still be a component hash: %+v", small.Hashes)
	}
}

// TestPartialScanIsNotExecutionSuccessful pins F28. executionSuccessful was a
// constant true, so a SARIF consumer recorded an unreadable path or a cancelled
// walk as a clean, complete run.
func TestPartialScanIsNotExecutionSuccessful(t *testing.T) {
	readRun := func(t *testing.T, rep *Report) (bool, []string) {
		t.Helper()
		var buf bytes.Buffer
		if err := rep.WriteSARIF(&buf); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Invocations []struct {
					ExecutionSuccessful bool `json:"executionSuccessful"`
					Notifications       []struct {
						Level   string `json:"level"`
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"toolExecutionNotifications"`
				} `json:"invocations"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
			t.Fatalf("no invocation in %s", buf.String())
		}
		inv := doc.Runs[0].Invocations[0]
		var msgs []string
		for _, n := range inv.Notifications {
			msgs = append(msgs, n.Level+": "+n.Message.Text)
		}
		return inv.ExecutionSuccessful, msgs
	}

	complete := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, NewCollector(0), Limits{}, nil, 0)
	if ok, msgs := readRun(t, complete); !ok || len(msgs) != 0 {
		t.Fatalf("a complete scan reported executionSuccessful=%v notifications=%v", ok, msgs)
	}

	partial := Build(Tool{Name: "sc4n", Version: "t"}, "", []ArtifactSummary{{Path: "gone.bin", Error: "no such file"}}, NewCollector(0), Limits{}, nil, 0)
	partial.Unreadable = 1
	ok, msgs := readRun(t, partial)
	if ok {
		t.Fatal("a scan with an unreadable path reported executionSuccessful=true")
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0], "1 path(s)") {
		t.Fatalf("notifications = %v, want one naming the unreadable count", msgs)
	}

	cancelled := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, NewCollector(0), Limits{}, nil, 0)
	cancelled.Cancelled = true
	if ok, msgs := readRun(t, cancelled); ok || len(msgs) != 1 {
		t.Fatalf("a cancelled scan reported executionSuccessful=%v notifications=%v", ok, msgs)
	}
}

// TestEveryFindingArtifactIsDeclared pins F27's invariant from the encoder side: a
// producer can report on a path it did not scan (the hf-cache expander reports a
// missing blob or a malformed ref), and CycloneDX requires every affects[].ref to
// name a declared bom-ref.
func TestEveryFindingArtifactIsDeclared(t *testing.T) {
	c := NewCollector(0)
	c.For("models--org--repo/snapshots/aaa/gone").Emit(testRuleInfo, 0, "resolved blob is missing")
	c.For("models--org--repo/refs/bad").Emit(testRuleInfo, 0, "refs/bad is not a 40-hex commit")
	c.For("scanned.bin").Emit(testRuleCritical, 1, "payload")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
		[]ArtifactSummary{{Path: "scanned.bin", Format: "pickle"}}, c, Limits{}, nil, 0)

	var buf bytes.Buffer
	if err := rep.WriteCycloneDX(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
		Vulnerabilities []struct {
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, comp := range doc.Components {
		declared[comp.BOMRef] = true
	}
	if len(declared) != 3 {
		t.Fatalf("declared %d components, want the scanned path plus the two named by findings: %v", len(declared), declared)
	}
	for _, v := range doc.Vulnerabilities {
		for _, a := range v.Affects {
			if !declared[a.Ref] {
				t.Errorf("affects[].ref %q names no declared bom-ref", a.Ref)
			}
		}
	}
}

// TestWritingOneFormatDoesNotChangeAnother pins F30a: WriteCycloneDX assigned
// "dev" to the report's own Tool.Version, so a later WriteJSON on the same report
// emitted a different version than the one the caller set.
func TestWritingOneFormatDoesNotChangeAnother(t *testing.T) {
	rep := Build(Tool{Name: "sc4n", Version: "1.2.3"}, "", nil, NewCollector(0), Limits{}, nil, 0)
	var cdx bytes.Buffer
	if err := rep.WriteCycloneDX(&cdx); err != nil {
		t.Fatal(err)
	}
	var json1 bytes.Buffer
	if err := rep.WriteJSON(&json1); err != nil {
		t.Fatal(err)
	}
	if rep.Tool.Version != "1.2.3" {
		t.Fatalf("WriteCycloneDX changed the report's tool version to %q", rep.Tool.Version)
	}
	if !strings.Contains(json1.String(), `"version": "1.2.3"`) {
		t.Fatalf("JSON after CycloneDX = %s", json1.String())
	}
	// The empty version is still rendered as "dev" in the BOM, without being
	// written back.
	empty := Build(Tool{Name: "sc4n"}, "", nil, NewCollector(0), Limits{}, nil, 0)
	var cdx2 bytes.Buffer
	if err := empty.WriteCycloneDX(&cdx2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cdx2.String(), `"version": "dev"`) {
		t.Fatalf("an empty tool version is not rendered as dev: %s", cdx2.String())
	}
	if empty.Tool.Version != "" {
		t.Fatalf("the report's tool version was mutated to %q", empty.Tool.Version)
	}
}

// TestTextCountsNestedFindings pins F30c: a finding inside a container is stamped
// "outer:member", so the container's own row showed FINDINGS 0 while its members
// carried the findings.
func TestTextCountsNestedFindings(t *testing.T) {
	c := NewCollector(0)
	c.For("outer.zip").Emit(testRuleInfo, 0, "outer-level")
	c.For("outer.zip").Named("inner.pkl").Emit(testRuleCritical, 4, "member-level")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
		[]ArtifactSummary{{Path: "outer.zip", Size: 12, Format: "zip"}}, c, Limits{}, nil, 0)
	var buf bytes.Buffer
	if err := rep.WriteText(&buf, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "outer.zip") {
			line = l
		}
	}
	if !strings.Contains(line, "2") {
		t.Fatalf("the container row does not count its member's finding: %q\n%s", line, buf.String())
	}
}

// TestTextEscapesControlBytesInPaths is the regression for the text encoder
// writing artifact paths raw: a file name may contain ESC, so a crafted name
// emitted ANSI sequences into the terminal or CI log, and a tab or newline broke
// the tabwriter table. JSON escapes them and SARIF percent-encodes them, so this
// was text-only.
func TestTextEscapesControlBytesInPaths(t *testing.T) {
	const name = "\x1b[31mRED\x1b[0m\tnew\nline.pkl"
	c := NewCollector(0)
	c.For(name).Emit(testRuleCritical, 4, "os.system")
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
		[]ArtifactSummary{{Path: name, Size: 12, Format: "pickle"}}, c, Limits{}, nil, 0)
	var buf bytes.Buffer
	if err := rep.WriteText(&buf, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("an escape byte reached the terminal output: %q", out)
	}
	// Both the artifact row and the LOCATION column render the name, and both
	// show the placeholder rather than the ESC bytes.
	if strings.Count(out, "·[31mRED·[0m new line.pkl") != 2 {
		t.Fatalf("the path was not escaped in both tables: %q", out)
	}
	// The tabs and the newline in the name became spaces, so the name did not
	// split the artifact row into extra columns: it still ends with the size and
	// finding-count columns.
	row := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "·[31mRED·[0m new line.pkl") {
			row = l
		}
	}
	if row == "" {
		t.Fatalf("the artifact row was not rendered as one line: %q", out)
	}
	if !strings.HasSuffix(row, "12 B  1") {
		t.Fatalf("the crafted name reflowed the artifact row: %q", row)
	}
}

// TestArtifactResolutionHandlesColons: a path may itself contain ':' (a Windows
// drive letter, a URL, a file literally named "a:b.pkl"), so the member separator
// cannot be found by splitting at the first colon. The declared rows are the
// authority: an exact match wins, otherwise the longest row path that prefixes the
// name wins.
func TestArtifactResolutionHandlesColons(t *testing.T) {
	arts := []ArtifactSummary{
		{Path: "a:b.pkl"},
		{Path: "outer.zip"},
		{Path: "outer.zip:inner.zip"},
	}
	ix := newArtifactIndex(arts)
	cases := []struct {
		in     string
		path   string
		member string
		ok     bool
	}{
		{"a:b.pkl", "a:b.pkl", "", true},
		{"outer.zip", "outer.zip", "", true},
		{"outer.zip:member.pkl", "outer.zip", "member.pkl", true},
		{"outer.zip:inner.zip:x.pkl", "outer.zip:inner.zip", "x.pkl", true},
		{"missing.pkl", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		path, member, ok := ix.resolve(tc.in)
		if path != tc.path || member != tc.member || ok != tc.ok {
			t.Errorf("resolve(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, path, member, ok, tc.path, tc.member, tc.ok)
		}
	}

	// A finding on a declared path must not add a second row, and a finding on a
	// name nothing declares is declared whole (never truncated to a phantom).
	got := declareFindingArtifacts(arts, []Finding{
		{RuleID: "X", Artifact: "a:b.pkl"},
		{RuleID: "X", Artifact: "outer.zip:member.pkl"},
		{RuleID: "X", Artifact: "dangling:thing"},
	})
	var paths []string
	for _, a := range got {
		paths = append(paths, a.Path)
	}
	want := []string{"a:b.pkl", "outer.zip", "outer.zip:inner.zip", "dangling:thing"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("rows = %v, want %v", paths, want)
	}
}

// TestDeclaredRowsAreNotCountedAsScanned: report.Build synthesises a row for every
// path a finding names that has no summary, so an encoder's reference resolves. A
// scan of one file that also reports two hf-cache ref findings declared three
// artifacts, and SARIF said artifactsScanned: 3.
func TestDeclaredRowsAreNotCountedAsScanned(t *testing.T) {
	c := NewCollector(0)
	c.For("refs/main").EmitExtra(testRuleInfo, 0, "malformed ref", nil)
	c.For("blobs/deadbeef").EmitExtra(testRuleInfo, 0, "missing blob", nil)
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
		[]ArtifactSummary{{Path: "m.bin", Size: 1, Format: "text"}}, c, Limits{}, nil, 0)

	if len(rep.Artifacts) != 3 {
		t.Fatalf("rows = %d, want 3 (one scanned plus two declared)", len(rep.Artifacts))
	}
	if rep.Scanned() != 1 {
		t.Fatalf("Scanned() = %d, want 1", rep.Scanned())
	}
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary struct {
			Artifacts int  `json:"artifacts"`
			Scanned   int  `json:"scanned"`
			Cancelled bool `json:"cancelled"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Artifacts != 3 || doc.Summary.Scanned != 1 {
		t.Fatalf("summary = %+v, want artifacts 3 scanned 1", doc.Summary)
	}
	if !strings.Contains(rep.SummaryLine(), "1 artifact(s) (2 declared by a finding, not scanned)") {
		t.Fatalf("SummaryLine() = %q", rep.SummaryLine())
	}
	for _, a := range rep.Artifacts {
		if a.Path == "m.bin" && a.NotScanned {
			t.Fatal("a scanned row was marked NotScanned")
		}
	}
}

// TestParseSeverityAcceptsTheEmptyString: -fail-on's documented default is the
// zero value, so an explicitly empty value must mean info rather than a usage
// error. The doc comment said so while the loop could never match "".
func TestParseSeverityAcceptsTheEmptyString(t *testing.T) {
	sev, err := ParseSeverity("")
	if err != nil {
		t.Fatalf(`ParseSeverity(""): %v`, err)
	}
	if sev != SeverityInfo {
		t.Fatalf(`ParseSeverity("") = %v, want info`, sev)
	}
}

// TestTruncateEvidenceKeepsRunesWhole: a byte-offset cut splits a multi-byte rune,
// and the report then carries a dangling sequence where the stream had a valid
// one. The cut backs off to the next rune start.
func TestTruncateEvidenceKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"ascii and more", 5, "ascii…"},
		{"éééééééééé", 5, "éé…"},
		{"éééééééééé", 4, "éé…"},
		{"日本語のテキスト", 7, "日本…"},
		{"short", 20, "short"},
		{"", 4, ""},
		{"é", 1, "…"},
	} {
		got := TruncateEvidence(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("TruncateEvidence(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("TruncateEvidence(%q, %d) = %q, which is not valid UTF-8", tc.in, tc.n, got)
		}
	}
}

func TestSARIFUnregisteredRuleDeduplicatedAndRegionCompliance(t *testing.T) {
	zeroLine := 0
	c := NewCollector(0)
	c.Add(Finding{
		RuleID: "SC4N-UNREG-TEST", Title: "unreg", Severity: SeverityHigh,
		Confidence: ConfidenceHigh, Artifact: "a:b.pkl", Offset: 0, Evidence: "ev1",
	})
	c.Add(Finding{
		RuleID: "SC4N-UNREG-TEST", Title: "unreg", Severity: SeverityHigh,
		Confidence: ConfidenceHigh, Artifact: "a:b.pkl", Offset: 10, Evidence: "ev2",
	})
	c.Add(Finding{
		RuleID: testRuleInfo.ID, Title: testRuleInfo.Title, Severity: SeverityInfo,
		Confidence: ConfidenceLow, Artifact: "a:b.pkl", Line: &zeroLine, Evidence: "line-only",
	})
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", []ArtifactSummary{{Path: "a:b.pkl", Format: "pickle"}}, c, Limits{}, nil, 0)

	var buf bytes.Buffer
	if err := rep.WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if strings.Contains(raw, `\u0000`) {
		t.Fatalf("SARIF output contains literal NUL escape: %s", raw)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine  int    `json:"startLine"`
							ByteOffset *int64 `json:"byteOffset"`
							ByteLength *int   `json:"byteLength"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	unregCount := 0
	for _, ru := range doc.Runs[0].Tool.Driver.Rules {
		if ru.ID == "SC4N-UNREG-TEST" {
			unregCount++
		}
	}
	if unregCount != 1 {
		t.Fatalf("unregistered rule emitted %d descriptors, want 1", unregCount)
	}
	for _, res := range doc.Runs[0].Results {
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "./a:b.pkl" {
			t.Errorf("URI for a:b.pkl = %q, want ./a:b.pkl", loc.ArtifactLocation.URI)
		}
		if loc.Region.StartLine < 1 {
			t.Errorf("StartLine = %d, want >= 1", loc.Region.StartLine)
		}
		if loc.Region.ByteLength != nil && loc.Region.ByteOffset == nil {
			t.Errorf("SARIF §3.30.14 violation: byteLength=%d without byteOffset", *loc.Region.ByteLength)
		}
		if res.RuleID == testRuleInfo.ID {
			if loc.Region.ByteOffset != nil || loc.Region.ByteLength != nil {
				t.Errorf("line-only finding carried byteOffset/byteLength: %+v", loc.Region)
			}
		} else if res.RuleID == "SC4N-UNREG-TEST" && loc.Region.ByteOffset == nil {
			t.Errorf("offset finding missing byteOffset (including 0)")
		}
		if strings.ContainsRune(res.PartialFingerprints["primaryLocationLineHash"], '\x00') {
			t.Errorf("primaryLocationLineHash contains NUL: %q", res.PartialFingerprints["primaryLocationLineHash"])
		}
	}
}

func TestSARIFPathURI(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"dir/m.pkl", "dir/m.pkl"},
		{"./dir/m.pkl", "dir/m.pkl"},
		{"a:b.pkl", "./a:b.pkl"},
		{"./a:b.pkl", "./a:b.pkl"},
		{"dir/a:b.pkl", "dir/a:b.pkl"},
		{"http://example.com/a.pkl", "http://example.com/a.pkl"},
	}
	for _, tc := range cases {
		if got := pathURI(tc.in); got != tc.want {
			t.Errorf("pathURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTextCancelledSummaryAndBidiC1Masking(t *testing.T) {
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, NewCollector(0), Limits{}, nil, 0)
	rep.Cancelled = true
	if !strings.Contains(rep.SummaryLine(), "cancelled") {
		t.Fatalf("SummaryLine() = %q, missing cancelled", rep.SummaryLine())
	}
	raw := "a\u0085b\u009fc\u202ed\u2066e\u2069f"
	got := collapseControl(raw)
	if got != "a·b·c·d·e·f" {
		t.Fatalf("collapseControl(%q) = %q, want %q", raw, got, "a·b·c·d·e·f")
	}
}

func TestCycloneDXSerialNumberCWEsAndEmptyArtifact(t *testing.T) {
	render := func(mod func(*Report)) (string, []byte) {
		c := NewCollector(0)
		c.For("m.pkl").Emit(testRuleCritical, 1, "os.system")
		rep := Build(Tool{Name: "sc4n", Version: "t"}, "",
			[]ArtifactSummary{{Path: "m.pkl", SHA256: "aa", SHA256Scope: "full", Format: "pickle"}}, c, Limits{}, nil, 0)
		if mod != nil {
			mod(rep)
		}
		var buf bytes.Buffer
		if err := rep.WriteCycloneDX(&buf); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Serial string `json:"serialNumber"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Serial, buf.Bytes()
	}

	baseSerial, baseBytes := render(nil)
	for name, mod := range map[string]func(*Report){
		"cancelled":  func(r *Report) { r.Cancelled = true },
		"unreadable": func(r *Report) { r.Unreadable = 1 },
		"suppressed": func(r *Report) { r.Suppressed = 2 },
		"dropped":    func(r *Report) { r.Dropped = 3 },
		"art error":  func(r *Report) { r.Artifacts[0].Error = "boom" },
		"art scope":  func(r *Report) { r.Artifacts[0].SHA256Scope = "prefix:16" },
	} {
		s, _ := render(mod)
		if s == baseSerial {
			t.Errorf("serialNumber did not change for %s", name)
		}
	}

	var doc struct {
		Vulnerabilities []struct {
			CWEs    []int `json:"cwes"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(baseBytes, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 || len(doc.Vulnerabilities[0].CWEs) != 1 || doc.Vulnerabilities[0].CWEs[0] != 502 {
		t.Fatalf("cwes = %+v, want [502]", doc.Vulnerabilities)
	}

	// Empty artifact must not produce a dangling "sc4n:" bom-ref.
	cEmpty := NewCollector(0)
	cEmpty.Add(Finding{RuleID: testRuleInfo.ID, Title: "t", Severity: SeverityInfo, Artifact: "", Evidence: "ev"})
	repEmpty := Build(Tool{Name: "sc4n", Version: "t"}, "", nil, cEmpty, Limits{}, nil, 0)
	var emptyBuf bytes.Buffer
	if err := repEmpty.WriteCycloneDX(&emptyBuf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(emptyBuf.String(), `"sc4n:"`) {
		t.Fatalf("dangling empty bom-ref emitted: %s", emptyBuf.String())
	}
}

func TestCollectorSuppressAndNoteRuleMaintainHeap(t *testing.T) {
	c := NewCollector(2)
	c.Add(Finding{RuleID: testRuleInfo.ID, Severity: SeverityInfo, Artifact: "a", Offset: 1, Evidence: "i"})
	c.Add(Finding{RuleID: testRuleHigh.ID, Severity: SeverityHigh, Artifact: "a", Offset: 2, Evidence: "h"})
	fp := map[string]bool{Fingerprint(Finding{RuleID: testRuleHigh.ID, Artifact: "a", Offset: 2, Evidence: "h"}): true}
	if n := c.Suppress(fp); n != 1 {
		t.Fatalf("Suppress = %d, want 1", n)
	}
	if c.Suppressed() != 1 {
		t.Fatalf("Suppressed() = %d, want 1", c.Suppressed())
	}
	// Adding two more findings after Suppress must still evict the lowest-severity
	// finding (info) cleanly.
	c.Add(Finding{RuleID: testRuleMedium.ID, Severity: SeverityMedium, Artifact: "a", Offset: 3, Evidence: "m"})
	c.Add(Finding{RuleID: testRuleCritical.ID, Severity: SeverityCritical, Artifact: "a", Offset: 4, Evidence: "c"})
	got := c.Findings()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, f := range got {
		if f.Severity == SeverityInfo {
			t.Fatalf("heap invariant broken: info finding survived over higher severities: %+v", got)
		}
	}
	// NoteRule on a capped collector keeps the heap valid as well.
	c.NoteRule(testRuleInfo, "a", 99, "notice", nil)
	if c.Len() != 3 {
		t.Fatalf("Len after NoteRule = %d, want 3", c.Len())
	}
}

func TestSinkDuplicateDistinguishesExtraRedactedAndPositionKind(t *testing.T) {
	c := NewCollector(0)
	s := c.For("f.py")
	s.Emit(testRuleInfo, 0, "same")
	s.EmitAt(testRuleInfo, 0, 0, "same")
	s.EmitExtra(testRuleInfo, 10, "ev", map[string]string{"k": "v1"})
	s.EmitExtra(testRuleInfo, 10, "ev", map[string]string{"k": "v2"})
	s.EmitExtra(testRuleInfo, 20, "secret", nil)
	s.EmitRedacted(testRuleInfo, 20, "secret", nil)
	// True duplicates are still collapsed.
	s.EmitExtra(testRuleInfo, 10, "ev", map[string]string{"k": "v1"})
	s.EmitRedacted(testRuleInfo, 20, "secret", nil)

	if got := len(c.Findings()); got != 6 {
		t.Fatalf("got %d findings, want 6 distinct findings: %+v", got, c.Findings())
	}
}

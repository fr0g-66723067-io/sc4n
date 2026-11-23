package content

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func contentCtx(t *testing.T) (*artifact.Ctx, *report.Collector) {
	t.Helper()
	c := report.NewCollector(0)
	l := limits.Default()
	sess := artifact.NewSession(c, "", l)
	return sess.NewCtx("x", l), c
}

func TestChatTemplateCapEmitsLimitFinding(t *testing.T) {
	ctx, c := contentCtx(t)
	var b strings.Builder
	b.WriteString(`{"chat_template":[`)
	for i := 0; i <= ctx.Limits.MaxChatTemplates; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"name":"t","template":"{{ x }}"}`)
	}
	b.WriteString(`]}`)
	chatTemplateRule(ctx, "tokenizer_config.json", []byte(b.String()))
	if !hasRule(c.Findings(), "SC4N-LIMIT-ENTRIES") {
		t.Fatalf("chat-template cap was silent; findings=%v", c.Findings())
	}
}

func TestNonLFSMergeDriverIsReported(t *testing.T) {
	ctx, c := contentCtx(t)
	gitAttributes(ctx, ".gitattributes", []byte("*.bin merge=custom\n"))
	if !hasRule(c.Findings(), "SC4N-GITATTRIBUTES-FILTER") {
		t.Fatalf("merge driver was silent; findings=%v", c.Findings())
	}
}

func TestBuiltinDiffDriverIsReportedAtInfo(t *testing.T) {
	ctx, c := contentCtx(t)
	gitAttributes(ctx, ".gitattributes", []byte("*.py diff=python\n"))
	if !hasRule(c.Findings(), "SC4N-GITATTRIBUTES-DIFF-NAME") {
		t.Fatalf("built-in diff driver was silent; findings=%v", c.Findings())
	}
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-GITATTRIBUTES-DIFF-NAME" && f.Severity != report.SeverityInfo {
			t.Fatalf("diff-name severity = %s", f.Severity)
		}
	}
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

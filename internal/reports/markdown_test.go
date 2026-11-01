package reports

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func flattenMarkdown(nodes []MarkdownNode) (kinds, content string) {
	for _, n := range nodes {
		kinds += " " + n.Kind
		content += n.Text
		ck, ct := flattenMarkdown(n.Children)
		kinds += ck
		content += ct
	}
	return
}
func TestMarkdownFormattingAndUnsafeContent(t *testing.T) {
	source := "# Advisory\n\n**Upgrade** *now* with `npm update`. &amp; \\*literal\\*\n\n- First\n  - Nested\n\n3. Third\n4. Fourth\n\n> Quoted guidance\n\n```sh\nnpm update <package>\n```\n\n| Package | Fixed |\n| --- | ---: |\n| example | 2.0 |\n\n[Safe](https://example.com/fix) [Unsafe](javascript:alert%281%29)\n\n![No remote image](https://example.com/tracker.png)\n\n<script>window.injected=true</script>\n\n<details>\n<summary>Details</summary>\n\n**Visible advisory**\n\n</details>"
	budget := &markdownBudget{remaining: 2048}
	nodes := markdownDocument(source, budget)
	kinds, content := flattenMarkdown(nodes)
	for _, kind := range []string{" h1", " strong", " em", " code", " ul", " ol", " li", " blockquote", " pre", " table", " th", " td", " a"} {
		if !strings.Contains(kinds, kind) {
			t.Fatalf("missing %s: %s", kind, kinds)
		}
	}
	for _, value := range []string{"& *literal*", "npm update <package>", "No remote image", "Visible advisory", "Unsafe"} {
		if !strings.Contains(content, value) {
			t.Fatalf("missing text %q: %s", value, content)
		}
	}
	encoded, _ := json.Marshal(nodes)
	for _, value := range []string{"javascript:", "tracker.png", "window.injected", "<summary>"} {
		if strings.Contains(string(encoded), value) {
			t.Fatalf("unsafe content survived: %s", value)
		}
	}
	if budget.exceeded {
		t.Fatal("normal content exceeded budget")
	}
}
func TestMarkdownSafeLinks(t *testing.T) {
	for _, value := range []string{"javascript:alert(1)", "JaVaScRiPt:alert(1)", "jav&#x61;script:alert(1)", "data:text/html,test", "file:///etc/passwd", "//example.com", "/relative", "https://user:pass@example.com", "https://example.com/\n"} {
		if safeMarkdownURL(value) != "" {
			t.Fatalf("unsafe URL accepted: %q", value)
		}
	}
	if safeMarkdownURL("https://example.com/?a=1&amp;b=2") != "https://example.com/?a=1&b=2" {
		t.Fatal("entity in URL not decoded")
	}
}
func TestFindingMarkdownUsesDedicatedFieldsAndLeavesPlainTextAlone(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner","rules":[{"id":"R","fullDescription":{"text":"Plain description","markdown":"**Formatted description**"},"help":{"text":"Plain guidance","markdown":"## Upgrade\n\nUse [this advisory](https://example.com/fix)."}}]}},"results":[{"ruleId":"R","message":{"text":"Finding"},"fixes":[{"description":{"text":"Plain fix","markdown":"Update to \u00602.0\u0060"}}]}]}]}`)
	report, _, err := s.Import(ctx, "ws", "actor", "markdown.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(ctx, "ws", report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.Description != "Plain description" || d.Guidance != "Plain guidance" || d.Markup == nil {
		t.Fatalf("detail: %+v", d)
	}
	kinds, text := flattenMarkdown(d.Markup.Description)
	if !strings.Contains(kinds, "strong") || text != "Formatted description" {
		t.Fatalf("wrong Markdown: %s %s", kinds, text)
	}
	kinds, text = flattenMarkdown(d.Markup.Fixes[0])
	if !strings.Contains(kinds, "code") || !strings.Contains(text, "2.0") {
		t.Fatal("fix Markdown missing")
	}
	raw = []byte(strings.ReplaceAll(string(raw), `"markdown":`, `"ignoredMarkdown":`))
	report, _, err = s.Import(ctx, "ws", "actor", "plain.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.Finding(ctx, "ws", report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.Markup != nil && (len(d.Markup.Description) > 0 || len(d.Markup.Guidance) > 0) {
		t.Fatal("plain text interpreted as Markdown")
	}
	if d.Description != "Plain description" || d.Guidance != "Plain guidance" {
		t.Fatal("plain text changed")
	}
}
func TestMarkdownBudgetFallsBackToPlainDetail(t *testing.T) {
	budget := &markdownBudget{remaining: 20}
	if nodes := markdownDocument(strings.Repeat("**word** ", 1000), budget); nodes != nil || !budget.exceeded {
		t.Fatal("oversized document not bounded")
	}
}

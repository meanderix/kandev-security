package reports

import (
	"html"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// MarkdownNode is an allowlisted document, never HTML. The UI creates React
// elements from it without accepting arbitrary tags, attributes, or image URLs.
type MarkdownNode struct {
	Kind     string         `json:"kind"`
	Text     string         `json:"text,omitempty"`
	URL      string         `json:"url,omitempty"`
	Start    *int           `json:"start,omitempty"`
	Align    string         `json:"align,omitempty"`
	Children []MarkdownNode `json:"children,omitempty"`
}
type FindingMarkup struct {
	Description []MarkdownNode   `json:"description,omitempty"`
	Guidance    []MarkdownNode   `json:"guidance,omitempty"`
	Fixes       [][]MarkdownNode `json:"fixes,omitempty"`
}
type markdownBudget struct {
	remaining int
	exceeded  bool
}

func markdownDocument(source string, budget *markdownBudget) []MarkdownNode {
	if source == "" {
		return nil
	}
	parser := goldmark.New(goldmark.WithExtensions(extension.GFM)).Parser()
	raw := []byte(source)
	doc := parser.Parse(text.NewReader(raw))
	var convert func(ast.Node, int) []MarkdownNode
	var children func(ast.Node, int) []MarkdownNode
	children = func(node ast.Node, depth int) []MarkdownNode {
		var result []MarkdownNode
		for child := node.FirstChild(); child != nil; child = child.NextSibling() {
			result = append(result, convert(child, depth+1)...)
			if budget.exceeded {
				break
			}
		}
		return result
	}
	convert = func(node ast.Node, depth int) []MarkdownNode {
		budget.remaining--
		if budget.remaining < 0 || depth > 32 {
			budget.exceeded = true
			return nil
		}
		n := MarkdownNode{}
		switch v := node.(type) {
		case *ast.HTMLBlock, *ast.RawHTML:
			return nil
		case *ast.Text:
			n.Kind = "text"
			n.Text = string(v.Value(raw))
			if !v.IsRaw() {
				n.Text = html.UnescapeString(string(util.UnescapePunctuations([]byte(n.Text))))
			}
			if v.SoftLineBreak() {
				n.Text += "\n"
			}
			if v.HardLineBreak() {
				return []MarkdownNode{n, {Kind: "br"}}
			}
		case *ast.String:
			n.Kind = "text"
			n.Text = string(v.Value)
			if !v.IsRaw() {
				n.Text = html.UnescapeString(string(util.UnescapePunctuations(v.Value)))
			}
		case *ast.CodeSpan:
			n.Kind = "code"
			for child := v.FirstChild(); child != nil; child = child.NextSibling() {
				n.Text += strings.ReplaceAll(string(child.(*ast.Text).Value(raw)), "\n", " ")
			}
		case *ast.CodeBlock, *ast.FencedCodeBlock:
			n.Kind = "pre"
			lines := node.Lines()
			n.Text = string(lines.Value(raw))
		case *ast.Heading:
			n.Kind = "h" + strconv.Itoa(v.Level)
		case *ast.Paragraph:
			n.Kind = "p"
		case *ast.TextBlock:
			n.Kind = "span"
		case *ast.Blockquote:
			n.Kind = "blockquote"
		case *ast.ThematicBreak:
			n.Kind = "hr"
		case *ast.Emphasis:
			n.Kind = "em"
			if v.Level == 2 {
				n.Kind = "strong"
			}
		case *ast.List:
			n.Kind = "ul"
			if v.IsOrdered() {
				n.Kind = "ol"
				start := v.Start
				n.Start = &start
			}
		case *ast.ListItem:
			n.Kind = "li"
		case *ast.Link:
			n.Kind = "a"
			n.URL = safeMarkdownURL(string(v.Destination))
			if n.URL == "" {
				n.Kind = "span"
			}
		case *ast.AutoLink:
			n.Kind = "a"
			n.Text = string(v.Label(raw))
			n.URL = safeMarkdownURL(string(v.URL(raw)))
			if n.URL == "" {
				n.Kind = "span"
			}
		case *ast.Image:
			// Display alt text without loading any image or remote resource.
			n.Kind = "span"
		case *east.Strikethrough:
			n.Kind = "del"
		case *east.TaskCheckBox:
			n.Kind = "text"
			n.Text = "☐ "
			if v.IsChecked {
				n.Text = "☑ "
			}
		case *east.Table:
			n.Kind = "table"
		case *east.TableHeader, *east.TableRow:
			n.Kind = "tbody"
			if node.Kind() == east.KindTableHeader {
				n.Kind = "thead"
			}
			n.Children = []MarkdownNode{{Kind: "tr", Children: children(node, depth)}}
			return []MarkdownNode{n}
		case *east.TableCell:
			n.Kind = "td"
			if node.Parent().Kind() == east.KindTableHeader {
				n.Kind = "th"
			}
			if v.Alignment == east.AlignLeft || v.Alignment == east.AlignCenter || v.Alignment == east.AlignRight {
				n.Align = v.Alignment.String()
			}
		default:
			return children(node, depth)
		}
		if n.Text == "" {
			n.Children = children(node, depth)
		}
		return []MarkdownNode{n}
	}
	result := children(doc, 0)
	if budget.exceeded {
		return nil
	}
	return result
}
func safeMarkdownURL(value string) string {
	value = html.UnescapeString(string(util.UnescapePunctuations([]byte(value))))
	if strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || (strings.ToLower(parsed.Scheme) != "https" && strings.ToLower(parsed.Scheme) != "http") {
		return ""
	}
	return parsed.String()
}

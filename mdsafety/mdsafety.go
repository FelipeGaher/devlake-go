// Package mdsafety validates that a Markdown source string sticks to a safe
// subset: no raw HTML (covers iframes, svg, embedded media — none of which
// have a native Markdown syntax outside raw HTML), links restricted to
// https/mailto, images restricted to https (no mailto — meaningless as an
// image source), and bounded tree nesting depth. This is a write-time gate
// only — the backend never renders Markdown to HTML, it just refuses to
// persist anything outside the subset.
package mdsafety

import (
	"errors"
	"net/url"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
)

// MaxNestingDepth bounds the parsed AST's tree depth — guards against
// pathological deeply-nested input (e.g. hundreds of nested blockquotes),
// independent of the existing max-length validation on the source string.
const MaxNestingDepth = 10

var (
	ErrRawHTMLNotAllowed = errors.New("raw HTML is not allowed")
	ErrUnsafeLinkScheme  = errors.New("only https:// and mailto: links are allowed")
	ErrUnsafeImageScheme = errors.New("only https:// image sources are allowed")
	ErrNestingTooDeep    = errors.New("formatting is nested too deeply")
)

var md = goldmark.New(goldmark.WithExtensions(extension.Strikethrough))

// Validate parses source as Markdown and rejects anything outside the safe
// subset: headings, emphasis/strong, strikethrough, lists, blockquotes,
// inline code, fenced/indented code blocks, thematic breaks, https/mailto
// links, and https images are allowed. Raw HTML is not. Link/image scheme
// checks are allowlists, not denylists, so javascript:/data:/file:/
// vbscript:/anything-else is rejected by construction.
func Validate(source string) error {
	src := []byte(source)
	doc := md.Parser().Parse(text.NewReader(src))

	depth := 0
	maxDepth := 0
	var walkErr error

	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			depth--
			return ast.WalkContinue, nil
		}
		depth++
		if depth > maxDepth {
			maxDepth = depth
		}

		switch n.Kind() {
		case ast.KindHTMLBlock, ast.KindRawHTML:
			walkErr = ErrRawHTMLNotAllowed
			return ast.WalkStop, nil
		case ast.KindImage:
			img := n.(*ast.Image)
			if !isSafeScheme(string(img.Destination), false) {
				walkErr = ErrUnsafeImageScheme
				return ast.WalkStop, nil
			}
		case ast.KindLink:
			link := n.(*ast.Link)
			if !isSafeScheme(string(link.Destination), true) {
				walkErr = ErrUnsafeLinkScheme
				return ast.WalkStop, nil
			}
		case ast.KindAutoLink:
			autoLink := n.(*ast.AutoLink)
			if !isSafeScheme(string(autoLink.URL(src)), true) {
				walkErr = ErrUnsafeLinkScheme
				return ast.WalkStop, nil
			}
		}
		return ast.WalkContinue, nil
	})

	if walkErr != nil {
		return walkErr
	}
	if maxDepth > MaxNestingDepth {
		return ErrNestingTooDeep
	}
	return nil
}

// IsUnsafeMarkdownError reports whether err is one of Validate's sentinel
// errors — lets handlers map any of the four to the same HTTP response
// without enumerating them individually at every call site.
func IsUnsafeMarkdownError(err error) bool {
	return errors.Is(err, ErrRawHTMLNotAllowed) ||
		errors.Is(err, ErrUnsafeLinkScheme) ||
		errors.Is(err, ErrUnsafeImageScheme) ||
		errors.Is(err, ErrNestingTooDeep)
}

// isSafeScheme is an allowlist, not a denylist: javascript:/data:/file:/
// vbscript:/anything-else is rejected by construction. allowMailto is false
// for image sources (a mailto: image makes no sense) and true for links.
func isSafeScheme(dest string, allowMailto bool) bool {
	u, err := url.Parse(dest)
	if err != nil || u.Scheme == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" {
		return true
	}
	return allowMailto && scheme == "mailto"
}

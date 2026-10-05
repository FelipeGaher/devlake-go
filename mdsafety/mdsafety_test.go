package mdsafety

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate_RejectsUnsafeConstructs(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   error
	}{
		{"html block", "<div>hi</div>\n\nparagraph", ErrRawHTMLNotAllowed},
		{"inline html", "hello <span>world</span>", ErrRawHTMLNotAllowed},
		{"script tag", "<script>alert(1)</script>", ErrRawHTMLNotAllowed},
		{"iframe", "<iframe src=\"https://evil.example\"></iframe>", ErrRawHTMLNotAllowed},
		{"svg", "<svg onload=\"alert(1)\"></svg>", ErrRawHTMLNotAllowed},
		{"http image (not https)", "![alt](http://example.com/x.png)", ErrUnsafeImageScheme},
		{"javascript image", "![alt](javascript:alert(1))", ErrUnsafeImageScheme},
		{"data image", "![alt](data:image/png;base64,iVBORw0KGgo=)", ErrUnsafeImageScheme},
		{"mailto image (image src has no mailto exception)", "![alt](mailto:someone@example.com)", ErrUnsafeImageScheme},
		{"javascript link", "[click](javascript:alert(1))", ErrUnsafeLinkScheme},
		{"data link", "[click](data:text/html,<script>alert(1)</script>)", ErrUnsafeLinkScheme},
		{"file link", "[click](file:///etc/passwd)", ErrUnsafeLinkScheme},
		{"vbscript link", "[click](vbscript:msgbox(1))", ErrUnsafeLinkScheme},
		{"http link (not https)", "[click](http://example.com)", ErrUnsafeLinkScheme},
		{"relative link", "[click](/some/path)", ErrUnsafeLinkScheme},
		{"javascript autolink", "<javascript:alert(1)>", ErrUnsafeLinkScheme},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.source)
			if !errors.Is(err, c.want) {
				t.Errorf("Validate(%q) = %v, want %v", c.source, err, c.want)
			}
		})
	}
}

func TestValidate_RejectsExcessiveNesting(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxNestingDepth+5; i++ {
		b.WriteString("> ")
	}
	b.WriteString("too deep")
	if err := Validate(b.String()); !errors.Is(err, ErrNestingTooDeep) {
		t.Errorf("Validate(deeply nested blockquote) = %v, want %v", err, ErrNestingTooDeep)
	}
}

func TestValidate_AllowsSafeSubset(t *testing.T) {
	safe := `# Heading

## Subheading

**bold** and *italic* and ~~strikethrough~~

- bullet one
- bullet two

1. numbered one
2. numbered two

> a blockquote

inline ` + "`code`" + ` span

` + "```" + `
fenced code block
` + "```" + `

---

[a safe link](https://example.com)

[an email link](mailto:someone@example.com)

<https://example.com/autolink>

![a safe image](https://example.com/photo.png)
`
	if err := Validate(safe); err != nil {
		t.Errorf("Validate(safe subset) = %v, want nil", err)
	}
}

func TestValidate_EmptyIsSafe(t *testing.T) {
	if err := Validate(""); err != nil {
		t.Errorf("Validate(\"\") = %v, want nil", err)
	}
}

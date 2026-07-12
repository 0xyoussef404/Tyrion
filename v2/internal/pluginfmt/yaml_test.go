package pluginfmt

import "testing"

func TestParseScalarInlineAndBlock(t *testing.T) {
	src := `
# a comment
name: subfinder
binary: subfinder
args: ["-d", "{{target}}", "-silent"]
timeout: 10m
sources:
  - crtsh
  - wayback
`
	m, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if String(m, "name", "") != "subfinder" {
		t.Errorf("name=%v", m["name"])
	}
	args := List(m, "args")
	if len(args) != 3 || args[0] != "-d" || args[1] != "{{target}}" {
		t.Errorf("args=%v", args)
	}
	sources := List(m, "sources")
	if len(sources) != 2 || sources[1] != "wayback" {
		t.Errorf("sources=%v", sources)
	}
}

func TestParseCommentInQuotes(t *testing.T) {
	m, err := Parse(`args: ["a#b", "c"]`)
	if err != nil {
		t.Fatal(err)
	}
	if a := List(m, "args"); len(a) != 2 || a[0] != "a#b" {
		t.Errorf("quote-hash handling failed: %v", a)
	}
}

package engagement

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/policy"
)

// Error is one validation failure, named by file, line and key. Msg never
// holds a value the credential detector matched.
type Error struct {
	File string
	Line int
	Key  string
	Msg  string
	// NotAvailable marks a key this build recognizes but does not run yet.
	NotAvailable bool
}

func (e Error) Error() string { return fmt.Sprintf("%s:%d:%s: %s", e.File, e.Line, e.Key, e.Msg) }

// Errors is every failure found in one file, in line order.
type Errors []Error

func (es Errors) Error() string {
	lines := make([]string, len(es))
	for i, e := range es {
		lines[i] = e.Error()
	}
	return strings.Join(lines, "\n")
}

// parser walks the YAML tree against the File type before decoding, so an
// unknown key, a wrong shape or a credential is reported with its line and
// key path, and every key path's line is known to later checks.
type parser struct {
	file  string
	lines map[string]int // key path -> line
	errs  Errors
}

func (p *parser) fail(key, format string, args ...any) {
	p.errs = append(p.errs, Error{File: p.file, Line: p.line(key), Key: key, Msg: fmt.Sprintf(format, args...)})
}

// unavailable records a key this build reads but does not run yet.
func (p *parser) unavailable(key, format string, args ...any) {
	p.errs = append(p.errs, Error{File: p.file, Line: p.line(key), Key: key,
		Msg: fmt.Sprintf(format, args...) + ": not available in this build", NotAvailable: true})
}

// line returns the line of key, or of its nearest recorded parent: a key
// that is missing is reported where its parent is.
func (p *parser) line(key string) int {
	for k := key; k != ""; k = parentKey(k) {
		if l, ok := p.lines[k]; ok {
			return l
		}
	}
	return 1
}

func parentKey(k string) string {
	if strings.HasSuffix(k, "]") {
		if i := strings.LastIndex(k, "["); i > 0 {
			return k[:i]
		}
	}
	if i := strings.LastIndex(k, "."); i > 0 {
		return k[:i]
	}
	return ""
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// parse decodes raw into a File after the structural walk and the
// credential scan. It returns nil and the errors when either fails, since a
// file with a credential in it must not be read further.
func (p *parser) parse(raw []byte) *File {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		p.syntaxErr(err)
		return nil
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		p.fail("(file)", "the file is empty")
		return nil
	}
	// Only one document is read, so a second one would be dropped whole,
	// excludes and narrowing included. It is refused instead.
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case errors.Is(err, io.EOF):
	case err != nil:
		p.syntaxErr(err)
	default:
		p.errs = append(p.errs, Error{File: p.file, Line: next.Line, Key: "(file)",
			Msg: "a second YAML document: an engagement file is one document, and nothing after --- would be read"})
	}
	root := doc.Content[0]
	p.walk(root, reflect.TypeFor[File](), "")
	p.scanCredentials(raw, root)
	if len(p.errs) > 0 {
		return nil
	}
	var f File
	if err := root.Decode(&f); err != nil {
		// The walk accepts only shapes Decode reads; reaching this is a bug
		// in the walk, reported rather than hidden.
		p.fail("(file)", "%v", err)
		return nil
	}
	return &f
}

func (p *parser) syntaxErr(err error) {
	p.errs = append(p.errs, Error{File: p.file, Line: yamlErrLine(err), Key: "(file)", Msg: "not valid YAML: " + yamlErrMsg(err)})
}

// plain reports whether n is written out: no anchor, alias or explicit tag.
// A tag such as !!binary would let a value be decoded from text the
// credential scan never sees as written.
func (p *parser) plain(n *yaml.Node, key string) bool {
	switch {
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		p.fail(key, "anchors and aliases are not read: write the value out, so the file says what runs")
	case n.Style&yaml.TaggedStyle != 0:
		p.fail(key, "explicit tags such as !!binary are not read: write the value plainly")
	default:
		return true
	}
	return false
}

// mapKey checks one mapping key: written out, a plain string, and not
// repeated in its mapping. It records the key's line.
func (p *parser) mapKey(k *yaml.Node, key string, seen map[string]int) bool {
	if first, dup := seen[k.Value]; dup {
		p.lines[key] = k.Line
		p.fail(key, "appears twice in this mapping (first on line %d)", first)
		return false
	}
	seen[k.Value] = k.Line
	p.lines[key] = k.Line
	if !p.plain(k, key) {
		return false
	}
	if k.Tag == "!!merge" {
		p.fail(key, "merge keys are not read: write the keys out")
		return false
	}
	if k.Kind != yaml.ScalarNode || k.Tag != "!!str" && k.Tag != "!!int" {
		p.fail(key, "a key here must be a plain string")
		return false
	}
	return true
}

// walk checks n against t: mapping keys against yaml tags, node kinds
// against field kinds. It records each key's line under its dotted path,
// with list items as path[i].
func (p *parser) walk(n *yaml.Node, t reflect.Type, path string) {
	if !p.plain(n, path) {
		return
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			p.fail(path, "must be a mapping of keys")
			return
		}
		fields := yamlFields(t)
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			key := join(path, k.Value)
			if !p.mapKey(k, key, seen) {
				continue
			}
			ft, ok := fields[k.Value]
			if !ok {
				p.fail(key, "unknown key")
				continue
			}
			p.walk(v, ft, key)
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			p.fail(path, "must be a mapping")
			return
		}
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			key := join(path, k.Value)
			if !p.mapKey(k, key, seen) {
				continue
			}
			p.walk(v, t.Elem(), key)
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			// The value is not echoed: a misplaced one may be a credential,
			// which the scan after the walk reports by key only.
			if n.Kind == yaml.ScalarNode {
				p.fail(path, "must be a list: put the value in brackets, as in [value]")
			} else {
				p.fail(path, "must be a list")
			}
			return
		}
		for i, item := range n.Content {
			key := fmt.Sprintf("%s[%d]", path, i)
			p.lines[key] = item.Line
			p.walk(item, t.Elem(), key)
		}
	case reflect.String:
		if n.Kind != yaml.ScalarNode {
			p.fail(path, "must be a single value, not a list or mapping")
		}
	case reflect.Int:
		var i int
		if n.Kind != yaml.ScalarNode || n.Tag != "!!int" || n.Decode(&i) != nil {
			p.fail(path, "must be a whole number")
		}
	case reflect.Bool:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
			p.fail(path, "must be true or false")
		}
	}
}

// yamlFields maps each yaml key of t, inline structs flattened, to its type.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for f := range t.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if opts == "inline" {
			maps.Copy(out, yamlFields(f.Type))
			continue
		}
		if name != "" && name != "-" {
			out[name] = f.Type
		}
	}
	return out
}

// scanCredentials runs the credential detector over every decoded scalar,
// which catches escaped values, and over every raw line, which catches
// comments: the engagement file is copied verbatim into the run directory,
// so nothing in it may hold a credential. An error names the key and the
// detector, never the value.
func (p *parser) scanCredentials(raw []byte, root *yaml.Node) {
	flagged := map[int]bool{}
	report := func(line int, key, detector string) {
		if flagged[line] {
			return
		}
		flagged[line] = true
		p.errs = append(p.errs, Error{File: p.file, Line: line, Key: key, Msg: fmt.Sprintf(
			"holds a value shaped like a credential (detector %s): credentials come from the environment or the provider's own login, never from this file", detector)})
	}
	var visit func(n *yaml.Node, key string)
	visit = func(n *yaml.Node, key string) {
		switch n.Kind {
		case yaml.ScalarNode:
			if d, ok := policy.DetectCredential(n.Value); ok {
				report(n.Line, or(key, "(file)"), d)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := join(key, n.Content[i].Value)
				visit(n.Content[i], k)
				visit(n.Content[i+1], k)
			}
		default:
			for i, c := range n.Content {
				visit(c, fmt.Sprintf("%s[%d]", key, i))
			}
		}
	}
	visit(root, "")
	for i, l := range bytes.Split(raw, []byte("\n")) {
		if d, ok := policy.DetectCredential(string(l)); ok {
			report(i+1, p.keyAt(i+1), d)
		}
	}
	sort.SliceStable(p.errs, func(i, j int) bool { return p.errs[i].Line < p.errs[j].Line })
}

// keyAt names the deepest key that starts at or before line, so a value on a
// continuation line or a comment is named by the key it sits under.
func (p *parser) keyAt(line int) string {
	best, bestLine := "(file)", 0
	for k, l := range p.lines {
		if l <= line && (l > bestLine || l == bestLine && len(k) > len(best)) {
			best, bestLine = k, l
		}
	}
	return best
}

// yamlErrLine extracts the line from a yaml.v3 syntax error, 1 if none.
func yamlErrLine(err error) int {
	var n int
	msg := err.Error()
	if i := strings.Index(msg, "line "); i >= 0 {
		_, _ = fmt.Sscanf(msg[i:], "line %d", &n)
	}
	if n == 0 {
		return 1
	}
	return n
}

// yamlErrMsg drops yaml.v3's prefix and line, which Error already carries.
// The parser's message never quotes a scalar's value.
func yamlErrMsg(err error) string {
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "line ") {
		msg = msg[i+2:]
	}
	if te, ok := errors.AsType[*yaml.TypeError](err); ok {
		return strings.Join(te.Errors, "; ")
	}
	return msg
}

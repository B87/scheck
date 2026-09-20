package check

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Placeholder syntax: a whole token equal to "{name}".
var placeholderRe = regexp.MustCompile(`^\{([a-z][a-z0-9_]*)\}$`)

// Charsets for Path and Ident kinds (SPEC.md §3). Traversal is rejected here,
// before any policy decision, so PathPolicy only ever sees clean absolute paths.
var (
	pathCharsRe  = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	identCharsRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Placeholder returns the param name a token binds, or "" for a literal.
func Placeholder(token string) string {
	m := placeholderRe.FindStringSubmatch(token)
	if m == nil {
		return ""
	}
	return m[1]
}

// BindError explains why a set of parameters does not fit a check. Its
// message names the expected kinds so a model can correct the call.
type BindError struct {
	CheckID string
	Msg     string
}

func (e *BindError) Error() string { return "check " + e.CheckID + ": " + e.Msg }

// Bind substitutes params into Argv, validating each value by its kind.
// Every declared param must be supplied and nothing else may be.
func (c Check) Bind(params map[string]string) ([]string, error) {
	byName := make(map[string]Param, len(c.Params))
	for _, p := range c.Params {
		byName[p.Name] = p
	}
	for name := range params {
		if _, ok := byName[name]; !ok {
			return nil, &BindError{c.ID, fmt.Sprintf("unknown param %q; expects %s", name, c.paramSpec())}
		}
	}
	argv := make([]string, 0, len(c.Argv))
	for _, tok := range c.Argv {
		name := Placeholder(tok)
		if name == "" {
			argv = append(argv, tok)
			continue
		}
		p := byName[name]
		val, ok := params[name]
		if !ok {
			return nil, &BindError{c.ID, fmt.Sprintf("missing param %q (%s)", name, p.Kind)}
		}
		if err := ValidateParam(p, val); err != nil {
			return nil, &BindError{c.ID, err.Error()}
		}
		argv = append(argv, val)
	}
	return argv, nil
}

// ValidateParam checks a value against a param's kind.
func ValidateParam(p Param, val string) error {
	switch p.Kind {
	case KindPath:
		return validatePath(p.Name, val)
	case KindIdent:
		if !identCharsRe.MatchString(val) {
			return fmt.Errorf("param %q: ident must match %s", p.Name, identCharsRe)
		}
	case KindInt:
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("param %q: not an integer", p.Name)
		}
		if n < p.Min || n > p.Max {
			return fmt.Errorf("param %q: %d outside [%d, %d]", p.Name, n, p.Min, p.Max)
		}
	case KindEnum:
		if slices.Contains(p.Enum, val) {
			return nil
		}
		return fmt.Errorf("param %q: must be one of %s", p.Name, strings.Join(p.Enum, "|"))
	default:
		return fmt.Errorf("param %q: unknown kind %q", p.Name, p.Kind)
	}
	return nil
}

func validatePath(name, val string) error {
	if !pathCharsRe.MatchString(val) {
		return fmt.Errorf("param %q: path must match %s", name, pathCharsRe)
	}
	if !strings.HasPrefix(val, "/") {
		return fmt.Errorf("param %q: path must be absolute", name)
	}
	if slices.Contains(strings.Split(val, "/"), "..") {
		return fmt.Errorf("param %q: traversal (..) is not allowed", name)
	}
	return nil
}

func (c Check) paramSpec() string {
	if len(c.Params) == 0 {
		return "no params"
	}
	parts := make([]string, 0, len(c.Params))
	for _, p := range c.Params {
		s := p.Name + ":" + string(p.Kind)
		switch p.Kind {
		case KindEnum:
			s += "(" + strings.Join(p.Enum, "|") + ")"
		case KindInt:
			s += fmt.Sprintf("[%d..%d]", p.Min, p.Max)
		}
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

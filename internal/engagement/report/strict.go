package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	hostreport "github.com/b87/scheck/internal/report"
)

var (
	unmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	envelopeType    = reflect.TypeFor[hostreport.Envelope]()
)

// checkKeys walks a report's JSON and refuses what encoding/json would quietly
// accept: a key that matches a field only without regard to case, and a key
// written twice (the last one would win). Every object key must be, byte for
// byte, the json tag of a field of the type it is read into. The embedded
// host envelope is not walked: ReadJSON drops it.
func checkKeys(raw []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return walk(dec, t, "report", 0)
}

// maxDepth bounds how deep a report may nest. A report scheck writes nests
// a dozen levels; the bound keeps the key walk's recursion shallow whatever
// order the checks run in. It does not bound memory: free-form values
// (an outcome's detail, a derived value) decode into maps and slices at many
// times the size of their text.
const maxDepth = 64

func walk(dec *json.Decoder, t reflect.Type, path string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%s: nested more than %d levels", path, maxDepth)
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Interface {
		return walkAny(dec, path, depth)
	}
	if t == envelopeType || reflect.PointerTo(t).Implements(unmarshalerType) || t.Implements(unmarshalerType) {
		var skip json.RawMessage
		return dec.Decode(&skip)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			return walkObject(dec, t, path, depth)
		case '[':
			for dec.More() {
				var elem reflect.Type
				switch t.Kind() {
				case reflect.Slice, reflect.Array:
					elem = t.Elem()
				default:
					elem = reflect.TypeFor[any]()
				}
				if err := walk(dec, elem, path, depth+1); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
	}
	return nil
}

func walkObject(dec *json.Decoder, t reflect.Type, path string, depth int) error {
	var fields map[string]reflect.Type
	if t.Kind() == reflect.Struct {
		fields = map[string]reflect.Type{}
		collectFields(t, fields)
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := kt.(string)
		if seen[key] {
			return fmt.Errorf("%s: key %q is written twice", path, key)
		}
		seen[key] = true
		var ft reflect.Type
		switch t.Kind() {
		case reflect.Struct:
			var ok bool
			if ft, ok = fields[key]; !ok {
				return fmt.Errorf("%s: unknown field %q (field names match exactly, including case)", path, key)
			}
		case reflect.Map:
			ft = t.Elem()
		default:
			ft = reflect.TypeFor[any]()
		}
		if err := walk(dec, ft, path+"."+key, depth+1); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// collectFields maps each exported field's json name to its type, flattening
// embedded structs without a tag.
func collectFields(t reflect.Type, out map[string]reflect.Type) {
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				collectFields(ft, out)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
}

// walkAny reads a free-form value, refusing a key written twice in any
// object inside it.
func walkAny(dec *json.Decoder, path string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%s: nested more than %d levels", path, maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("%s: key %q is written twice", path, key)
			}
			seen[key] = true
			if err := walkAny(dec, path, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkAny(dec, path, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token()
	return err
}

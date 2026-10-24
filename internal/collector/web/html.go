package web

import (
	"html"
	"strings"
)

type htmlTag struct {
	name  string
	attrs map[string]string
}

// htmlTags reads only tags, ignoring comments and script/style bodies. It
// never interprets URLs or expands a site's request surface.
func htmlTags(body string) []htmlTag {
	var out []htmlTag
	skip := ""
	templateDepth := 0
	templateRaw := ""
	for len(body) > 0 {
		rawName := skip
		if skip == "template" {
			rawName = templateRaw
		}
		if rawName != "" && rawName != "template" {
			body = rawElementEnd(body, rawName)
			if body == "" {
				break
			}
		}
		i := strings.IndexByte(body, '<')
		if i < 0 {
			break
		}
		body = body[i:]
		if strings.HasPrefix(body, "<!--") {
			end := strings.Index(body, "-->")
			if end < 0 {
				break
			}
			body = body[end+3:]
			continue
		}
		end := -1
		quote := byte(0)
		for i := 1; i < len(body); i++ {
			b := body[i]
			if quote != 0 {
				if b == quote {
					quote = 0
				}
				continue
			}
			if b == '\'' || b == '"' {
				quote = b
			} else if b == '>' {
				end = i
				break
			}
		}
		if end < 0 {
			break
		}
		raw := body[1:end]
		if raw == "" || raw[0] <= 32 {
			body = body[end+1:]
			continue
		}
		body = body[end+1:]
		nameEnd := 0
		if raw[0] == '/' {
			nameEnd++
		}
		for nameEnd < len(raw) && !strings.ContainsRune(" \t\n\r\f/", rune(raw[nameEnd])) {
			nameEnd++
		}
		if nameEnd == 0 {
			continue
		}
		name := strings.ToLower(raw[:nameEnd])
		if skip == "template" {
			if templateRaw != "" {
				if name == "/"+templateRaw {
					templateRaw = ""
				}
				continue
			}
			if name == "template" {
				templateDepth++
			}
			if name == "/template" {
				templateDepth--
				if templateDepth == 0 {
					skip = ""
				}
			}
			if rawElement(name) {
				templateRaw = name
			}
			continue
		}
		if skip != "" {
			if name == "/"+skip {
				skip = ""
			}
			continue
		}
		if name == "plaintext" {
			break
		}
		if rawElement(name) || name == "template" {
			skip = name
			if name == "template" {
				templateDepth = 1
			}
			continue
		}
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "!") {
			continue
		}
		out = append(out, htmlTag{name: name, attrs: htmlAttributes(raw[nameEnd:])})
	}
	return out
}

// Consume whole attribute tokens, including malformed names, rather than
// discovering a valid-looking substring inside another attribute.
func htmlAttributes(raw string) map[string]string {
	attrs := map[string]string{}
	for len(raw) > 0 {
		raw = strings.TrimLeft(raw, " \t\n\r\f/")
		if raw == "" {
			break
		}
		i := 0
		for i < len(raw) && !strings.ContainsRune(" \t\n\r\f/=", rune(raw[i])) {
			i++
		}
		if i == 0 {
			raw = raw[1:]
			continue
		}
		key := strings.ToLower(raw[:i])
		raw = strings.TrimLeft(raw[i:], " \t\n\r\f")
		value := ""
		if strings.HasPrefix(raw, "=") {
			raw = strings.TrimLeft(raw[1:], " \t\n\r\f")
			if raw != "" && (raw[0] == '\'' || raw[0] == '"') {
				quote := raw[0]
				raw = raw[1:]
				end := strings.IndexByte(raw, quote)
				if end < 0 {
					break
				}
				value, raw = raw[:end], raw[end+1:]
			} else {
				end := 0
				for end < len(raw) && !strings.ContainsRune(" \t\n\r\f", rune(raw[end])) {
					end++
				}
				value, raw = raw[:end], raw[end:]
			}
		}
		if _, exists := attrs[key]; !exists {
			attrs[key] = html.UnescapeString(value)
		}
	}
	return attrs
}
func passwordForm(body string) bool {
	for _, t := range htmlTags(body) {
		if t.name == "input" && strings.EqualFold(t.attrs["type"], "password") {
			return true
		}
	}
	return false
}

func rawElement(name string) bool {
	return name == "script" || name == "style" || name == "textarea" || name == "title" || name == "xmp" || name == "iframe" || name == "noembed" || name == "noframes" || name == "noscript"
}

// Raw-text and RCDATA bodies do not tokenize HTML comments or attribute
// quotes. Script's escaped and double-escaped states still determine which
// end tag closes it (HTML Standard §13.2.5.15–31;
// https://html.spec.whatwg.org/multipage/parsing.html).
func rawElementEnd(body, name string) string {
	state := 0 // script data, escaped, double escaped
	for i := 0; i < len(body); i++ {
		if rawTagAt(body, i, "</"+name) {
			if name == "script" && state == 2 {
				state = 1
				i += len("</script") - 1
				continue
			}
			return body[i:]
		}
		if name != "script" {
			continue
		}
		switch {
		case state == 0 && strings.HasPrefix(body[i:], "<!--"):
			state = 1
			i += 3
		case state != 0 && strings.HasPrefix(body[i:], "-->"):
			state = 0
			i += 2
		case state == 1 && rawTagAt(body, i, "<script"):
			state = 2
			i += len("<script") - 1
		}
	}
	return ""
}

func rawTagAt(body string, at int, prefix string) bool {
	end := at + len(prefix)
	return end < len(body) && strings.EqualFold(body[at:end], prefix) && strings.ContainsRune(" \t\n\r\f/>", rune(body[end]))
}

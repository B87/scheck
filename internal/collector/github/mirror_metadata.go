package github

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/policy"
)

var errMirrorMismatch = errors.New("mirror_remote_mismatch")
var errMirrorFormat = errors.New("unsupported_mirror_format")
var errMirrorCorrupt = errors.New("corrupt_mirror")
var errMirrorChanged = errors.New("mirror_changed")
var sectionRE = regexp.MustCompile(`^\[([A-Za-z][A-Za-z0-9.-]*)(?:\s+"([^"\\]*)")?\]$`)
var configKeyRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// No source text or URL is included in errors or exported metadata.
// docs/spec/github-collector.md, "Mirror admission and confinement".
func parseMirrorConfig(raw []byte, asset string, detect func([]byte) ([]policy.SecretLocation, bool)) ([]policy.SecretLocation, error) {
	settings := map[string]string{}
	section := ""
	remoteSection := ""
	seen := map[string]bool{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			m := sectionRE.FindStringSubmatch(line)
			if m == nil {
				return nil, errMirrorFormat
			}
			section = strings.ToLower(m[1])
			remoteSection = m[2]
			// Subsections cannot stand in for the required ordinary settings.
			if (section == "core" || section == "extensions") && strings.Contains(line, "\"") {
				return nil, errMirrorFormat
			}
			if section == "include" || section == "includeif" || section == "url" {
				return nil, errMirrorFormat
			}
			if section == "remote" && remoteSection != "origin" {
				return nil, errMirrorFormat
			}
			continue
		}
		if section == "" {
			return nil, errMirrorFormat
		}
		k, v, has := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !configKeyRE.MatchString(k) {
			return nil, errMirrorFormat
		}
		k = strings.ToLower(k)
		if !has {
			v = "true"
		}
		value, err := configValue(v)
		if err != nil {
			return nil, err
		}
		full := section + "." + k
		if section == "extensions" && (k != "objectformat" || value != "sha1") {
			return nil, errMirrorFormat
		}
		if k == "promisor" || k == "partialclonefilter" || full == "core.worktree" || full == "core.refstorage" {
			return nil, errMirrorFormat
		}
		relevant := slices.Contains([]string{"core.bare", "core.repositoryformatversion", "remote.url", "remote.mirror", "remote.fetch", "extensions.objectformat"}, full)
		if relevant {
			if seen[full] {
				return nil, errMirrorFormat
			}
			seen[full] = true
			settings[full] = value
		}
	}
	if settings["core.bare"] != "true" || !slices.Contains([]string{"0", "1"}, settings["core.repositoryformatversion"]) || settings["remote.mirror"] != "true" || settings["remote.fetch"] != "+refs/*:refs/*" {
		return nil, errMirrorFormat
	}
	origin := settings["remote.url"]
	if origin == "" {
		return nil, errMirrorFormat
	}
	compare := strings.TrimPrefix(asset, "repo:github:")
	credential := false
	credentialBytes := 0
	var repo string
	if after, ok := strings.CutPrefix(origin, "git@github.com:"); ok {
		repo = after
		if strings.ContainsAny(repo, "?#:@\\") {
			return nil, errMirrorFormat
		}
	} else {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "ssh") || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
			return nil, errMirrorFormat
		}
		if u.User != nil {
			credentialBytes = len(u.User.String())
			_, password := u.User.Password()
			credential = password || u.Scheme == "https" && u.User.Username() != "" || u.Scheme == "ssh" && u.User.Username() != "git"
		}
		repo = strings.TrimPrefix(u.Path, "/")
	}
	repo = strings.TrimSuffix(repo, ".git")
	if !strings.EqualFold(repo, compare) {
		return nil, errMirrorMismatch
	}
	hits, complete := detect([]byte(origin))
	if !complete {
		return nil, gate.ErrMirrorLimit
	}
	if credential && len(hits) == 0 {
		hits = []policy.SecretLocation{{Rule: "url-credentials", Marker: policy.Marker("url-credentials", credentialBytes), Line: 1, Bytes: credentialBytes}}
	}
	return hits, nil
}
func configValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	var out strings.Builder
	quoted := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && (c == '#' || c == ';') {
			break
		}
		if c == '\\' {
			i++
			if i == len(v) {
				return "", errMirrorFormat
			}
			switch v[i] {
			case '\\', '"':
				c = v[i]
			case 'n':
				c = '\n'
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			default:
				return "", errMirrorFormat
			}
		}
		out.WriteByte(c)
	}
	if quoted {
		return "", errMirrorFormat
	}
	return strings.TrimSpace(out.String()), nil
}

type mirrorMetadata struct {
	config  []byte
	refs    map[string]string
	files   map[string][]byte
	release func()
}

func (s *mirrorScan) metadata() (mirrorMetadata, error) {
	release, err := s.reserve(32 << 20)
	if err != nil {
		return mirrorMetadata{}, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	m := mirrorMetadata{release: release, refs: map[string]string{}, files: map[string][]byte{}}
	b, err := s.files.Read("config", 64<<10)
	if err != nil {
		return m, err
	}
	m.config = b
	m.files["config"] = b
	for _, forbidden := range []string{"shallow", "objects/info/alternates", "objects/info/http-alternates", "info/grafts", "commondir"} {
		_, e := s.files.Read(forbidden, 64<<10)
		if e == nil || !os.IsNotExist(e) {
			s.gap("unsupported_mirror_layout")
		}
	}
	total := 0
	keep := func(name string, b []byte) error {
		total += len(b)
		if total > 8<<20 {
			return gate.ErrMirrorLimit
		}
		m.files[name] = b
		return nil
	}
	b, err = s.files.Read("packed-refs", 8<<20)
	if err == nil {
		if e := keep("packed-refs", b); e != nil {
			return m, e
		}
		previous := false
		for line := range strings.SplitSeq(string(b), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "^") {
				if !previous || !fullSHA.MatchString(line[1:]) {
					return m, errMirrorCorrupt
				}
				previous = false
				continue
			}
			parts := strings.Split(line, " ")
			if len(parts) != 2 || !fullSHA.MatchString(parts[0]) || !refOK(parts[1]) {
				return m, errMirrorCorrupt
			}
			if _, ok := m.refs[parts[1]]; ok {
				return m, errMirrorCorrupt
			}
			m.refs[parts[1]] = strings.ToLower(parts[0])
			previous = true
			if len(m.refs) > 10000 {
				return m, gate.ErrMirrorLimit
			}
		}
	} else if !os.IsNotExist(err) {
		return m, err
	}
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 128 {
			return gate.ErrMirrorLimit
		}
		items, listRelease, err := s.list(dir)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer listRelease()
		slices.SortFunc(items, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, entry := range items {
			name := path.Join(dir, entry.Name())
			if entry.IsDir() {
				if err := walk(name, depth+1); err != nil {
					return err
				}
				continue
			}
			if !refOK(name) {
				return errMirrorFormat
			}
			b, err := s.files.Read(name, 4096)
			if err != nil {
				return err
			}
			if err = keep(name, b); err != nil {
				return err
			}
			m.refs[name] = strings.TrimSpace(string(b))
			if len(m.refs) > 10000 {
				return gate.ErrMirrorLimit
			}
		}
		return nil
	}
	if err = walk("refs", 0); err != nil {
		return m, err
	}
	b, err = s.files.Read("HEAD", 4096)
	if err != nil {
		return m, err
	}
	if err = keep("HEAD", b); err != nil {
		return m, err
	}
	m.refs["HEAD"] = strings.TrimSpace(string(b))
	resolving := map[string]bool{}
	var resolve func(string, int) (string, error)
	resolve = func(name string, depth int) (string, error) {
		if depth > 16 {
			return "", gate.ErrMirrorLimit
		}
		if resolving[name] {
			return "", errMirrorCorrupt
		}
		v, ok := m.refs[name]
		if !ok {
			return "", errMirrorCorrupt
		}
		if fullSHA.MatchString(v) {
			return strings.ToLower(v), nil
		}
		if !strings.HasPrefix(v, "ref: ") || !refOK(v[5:]) {
			return "", errMirrorCorrupt
		}
		resolving[name] = true
		id, err := resolve(v[5:], depth+1)
		delete(resolving, name)
		return id, err
	}
	// An empty mirror can have an unborn HEAD.
	if len(m.refs) == 1 && strings.HasPrefix(m.refs["HEAD"], "ref: refs/heads/") && refOK(strings.TrimPrefix(m.refs["HEAD"], "ref: ")) {
		delete(m.refs, "HEAD")
	} else {
		for name := range m.refs {
			id, err := resolve(name, 0)
			if err != nil {
				return m, err
			}
			m.refs[name] = id
		}
	}
	for name := range m.refs {
		if strings.HasPrefix(name, "refs/replace/") {
			s.gap("replacement_refs_unassessed")
			delete(m.refs, name)
		}
	}
	success = true
	return m, nil
}
func refOK(name string) bool {
	if len(name) > 4096 || !strings.HasPrefix(name, "refs/") || strings.ContainsAny(name, " \x00\r\n\t~^:?*[\\") || strings.Contains(name, "@{") || strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") {
		return false
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") || strings.HasSuffix(part, ".") {
			return false
		}
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func sameMetadata(a, b mirrorMetadata) bool {
	if len(a.files) != len(b.files) {
		return false
	}
	for k, v := range a.files {
		if !bytes.Equal(v, b.files[k]) {
			return false
		}
	}
	return true
}
func objectID(raw []byte, kind string) string { return fmt.Sprintf("%x", gitHash(kind, raw)) }
func parseSize(s string) (int, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < 0 {
		return 0, errMirrorCorrupt
	}
	return n, nil
}

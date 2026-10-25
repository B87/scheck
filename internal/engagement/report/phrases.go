package report

// The report's own wording that a consumer of its JSON prints in the same
// words (the comparison of two runs, docs/spec/runs.md, "Comparing two
// runs"). Exported as methods and functions so a consumer never keeps a
// second copy of the phrases.

// ReasonPhrase is a reason's fixed phrase, as the text report words it. It is
// a method because some phrases name the engagement file this report was
// built from. The result is not escaped: the caller escapes what it prints.
func (r *Report) ReasonPhrase(rd ReasonDetail) string {
	return (&text{r: r}).reasonText(rd)
}

// AreaLabel is the plain name of a risk area key, or the key itself when
// this build has no name for it.
func AreaLabel(area string) string {
	if l, ok := areaLabel[area]; ok {
		return l
	}
	return area
}

// KindLabel names what kind of thing an asset id is, in words.
func KindLabel(id string) string { return kindLabel(id) }

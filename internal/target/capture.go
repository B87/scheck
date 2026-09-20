package target

// CapWriter stores at most Max bytes and drops the rest, remembering that it
// did. It never returns an error, so the child process is never killed by a
// broken pipe: output beyond the cap is simply discarded and the exit code
// stays meaningful.
type CapWriter struct {
	Max       int
	Buf       []byte
	Truncated bool
}

// Write implements io.Writer.
func (w *CapWriter) Write(p []byte) (int, error) {
	room := w.Max - len(w.Buf)
	switch {
	case room <= 0:
		w.Truncated = true
	case len(p) > room:
		w.Buf = append(w.Buf, p[:room]...)
		w.Truncated = true
	default:
		w.Buf = append(w.Buf, p...)
	}
	return len(p), nil
}

package local

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/target"
)

func TestExecLiteralArgv(t *testing.T) {
	// The whole point of the local target: no shell, so nothing expands.
	for _, hostile := range []string{"$(whoami)", "`id`", "$HOME", "a;b", "a|b", "*", "~"} {
		res, err := New(4096).Exec(context.Background(), []string{"echo", hostile})
		if err != nil {
			t.Fatalf("%q: %v", hostile, err)
		}
		if got := strings.TrimSpace(string(res.Stdout)); got != hostile {
			t.Errorf("echo %q: got %q, shell expansion happened", hostile, got)
		}
	}
}

func TestExecNonZeroExitIsNotAnError(t *testing.T) {
	res, err := New(4096).Exec(context.Background(), []string{"sh", "-c", "echo out; echo err >&2; exit 3"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 3 || strings.TrimSpace(string(res.Stdout)) != "out" || strings.TrimSpace(string(res.Stderr)) != "err" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestExecMissingBinary(t *testing.T) {
	res, err := New(4096).Exec(context.Background(), []string{"definitely-not-a-binary-xyz"})
	if !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if res.Code != target.CodeNotFound {
		t.Errorf("code = %d, want %d", res.Code, target.CodeNotFound)
	}
}

func TestExecTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := New(4096).Exec(ctx, []string{"sleep", "10"})
	if !errors.Is(err, target.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("kill did not take effect promptly")
	}
}

func TestExecOutputCap(t *testing.T) {
	res, err := New(1000).Exec(context.Background(), []string{"head", "-c", "50000", "/dev/zero"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 1000 || !res.StdoutTruncated {
		t.Errorf("len=%d truncated=%v, want 1000/true", len(res.Stdout), res.StdoutTruncated)
	}
	if res.Code != 0 {
		t.Errorf("cap must not break the child: code=%d", res.Code)
	}
}

func TestExecEmptyArgv(t *testing.T) {
	if _, err := New(10).Exec(context.Background(), nil); err == nil {
		t.Fatal("want error")
	}
}

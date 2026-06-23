package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRevoker(t *testing.T) {
	// nil / unconfigured revoker never revokes
	var r *revoker
	if r.revoked("123") {
		t.Fatal("nil revoker must not revoke")
	}
	r = &revoker{path: ""}
	if r.revoked("123") {
		t.Fatal("empty-path revoker must not revoke")
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "revoked")
	r = &revoker{path: p}

	// file absent => nothing revoked
	if r.revoked("123") {
		t.Fatal("absent file must not revoke")
	}

	// write two serials; both revoked, others not
	if err := os.WriteFile(p, []byte("123\n456\n  \n789"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"123", "456", "789"} {
		if !r.revoked(s) {
			t.Fatalf("serial %s should be revoked", s)
		}
	}
	if r.revoked("999") || r.revoked("") {
		t.Fatal("unlisted/empty serial must not revoke")
	}

	// hot-reload: append a serial, bump mtime, expect it picked up
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(p, []byte("999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// force a newer mtime in case the FS clock is coarse
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(p, future, future)
	if !r.revoked("999") {
		t.Fatal("hot-reload should pick up the new serial")
	}
	if r.revoked("123") {
		t.Fatal("removed serial should no longer revoke after reload")
	}
}

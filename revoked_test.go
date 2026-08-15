package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKnownLeakedTokenIsRevoked is the regression guard for the drift that let a leaked
// credential keep working. The payload below was shipped to every downloader by the
// 1.6.5-win release; it was revoked in the account server and in some game servers, and
// still accepted here.
func TestKnownLeakedTokenIsRevoked(t *testing.T) {
	const leaked = "1800000006.Kazuu.1787343209"
	if !revokedNexPayloads[leaked] {
		t.Fatalf("the payload leaked by the 1.6.5-win release is NOT revoked on this server")
	}
}

// TestRevokedListFromConfig covers the loader that makes the next revocation a config
// change on every server instead of nine source edits.
func TestRevokedListFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.txt")
	content := "# leaked in some future incident\n1800000123.Someone.1800000000\n\n1800000124.Other.1800000000 # inline comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXTENDO_REVOKED_TOKENS_FILE", path)
	t.Setenv("NEXTENDO_REVOKED_TOKENS", "1800000125.Env.1800000000,1800000126.Env2.1800000000")

	loadRevokedPayloads()

	for _, want := range []string{
		"1800000123.Someone.1800000000",
		"1800000124.Other.1800000000",
		"1800000125.Env.1800000000",
		"1800000126.Env2.1800000000",
	} {
		if !revokedNexPayloads[want] {
			t.Errorf("payload %q was not loaded from configuration", want)
		}
	}
	if revokedNexPayloads["# leaked in some future incident"] {
		t.Error("a comment line was loaded as a payload")
	}
}

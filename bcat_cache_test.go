package main

import "testing"

// [Audit Prelude #3] Le serveur ne doit JAMAIS émettre un chemin capable de sortir de l'arbre
// de sauvegarde : le homebrew le concatène aveuglément. Ce test fige ce qui est refusé.
func TestSafeBcatPath(t *testing.T) {
	ok := []string{
		"directories/vsdata/files/VSSetting_0.byaml",
		"list.msgpack",
		"directories/coop/files.meta",
		"etag.bin",
		"a/b/c/d.bin",
	}
	for _, p := range ok {
		if !safeBcatPath(p) {
			t.Errorf("chemin légitime refusé à tort : %q", p)
		}
	}

	bad := []string{
		"../atmosphere/hbmenu.nro",        // remontée directe
		"directories/../../../etc/passwd", // remontée enfouie
		"..",                              // remontée nue
		"/etc/shadow",                     // absolu
		"C:/Windows/System32/x",           // lettre de lecteur
		"file:with:colons",                // ADS / ":"
		"back\\slash",                     // antislash résiduel
		"nul\x00byte",                     // octet nul
		"",                                // vide
	}
	for _, p := range bad {
		if safeBcatPath(p) {
			t.Errorf("chemin DANGEREUX accepté : %q", p)
		}
	}

	// Longueur aberrante.
	long := make([]byte, bcatMaxPathLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if safeBcatPath(string(long)) {
		t.Error("chemin trop long accepté")
	}
}

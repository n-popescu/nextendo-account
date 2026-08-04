package main

import (
	"os"
	"testing"
)

// Vérifie le décodeur S2 Go contre la vraie save (doit lire Level 41, arme "Marqueur lourd 7").
// Chemin passé via S2_SAVE_PATH ; test ignoré si absent (CI).
func TestS2DecodeRealSave(t *testing.T) {
	p := os.Getenv("S2_SAVE_PATH")
	if p == "" {
		t.Skip("S2_SAVE_PATH non défini")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("lecture save: %v", err)
	}
	body := decodeS2Save(data)
	if body == nil {
		t.Fatal("decodeS2Save a renvoyé nil")
	}
	fields := s2Fields(body, "fr")
	if len(fields) == 0 {
		t.Fatal("aucun champ")
	}
	for _, f := range fields {
		t.Logf("  %s = %s", f.K, f.V)
	}
}

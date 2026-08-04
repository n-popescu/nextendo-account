package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// [Nextendo] Cloud-save CONTENT preview for the site's personal space.
//
// The stored blob (saveDir/<pid>/<titleId>.bin) is a zip of the Switch save directory the
// emulator uploaded (ApplicationHelper.ExportNextendoSave -> ZipFile.CreateFromDirectory).
// We unzip it in memory and read ONLY proven offsets to surface human-readable stats
// (e.g. MK8DX unlocked items). No guessing: a title without a verified parser returns an
// empty field list, and the site then just shows the save's size/date.
//
// Contract with the site (compte.html): each field is {k,v} where `k` is an i18n label
// suffix (the site renders T("save.field."+k)) and `v` is an already-formatted, language-
// neutral display value (a fraction, a number…). This keeps localisation on the site.

type saveField struct {
	K   string `json:"k"`
	V   string `json:"v"`
	Img string `json:"img,omitempty"` // optional icon URL (e.g. the S2 weapon)
}

// saveLang normalises a UI language code to the set the parsers localise into (English default).
func saveLang(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	switch l {
	case "en", "fr", "es", "pt", "de", "it", "ru", "zh", "ja", "ar":
		return l
	}
	return "en"
}

// MK8DX userdata.dat — proven layout. Header/unlock flags from the emulator's
// NextendoSaveEditor/Mk8dxSave.cs; the u32 stat offsets are the EdiZon community config
// (WerWolv/EdiZon_CheatsConfigsAndScripts, Configs/0100152000022000.json) and were verified
// against real saves (Race Rating read 987/994 — VR sits near its 1000 baseline, coins/races
// read small sane values on lightly-played saves). All stat words are little-endian u32.
//
//	0x0000  char[4]  magic "SUTC"
//	0x0048  char[4]  sub-magic "SUTC" (start of CRC region)
//	0x195C  u32      coins
//	0x1E94  u32      Race Rating   (VR — the online versus rating)
//	0x1E98  u32      Battle Rating (BR)
//	0x1E9C  u32      total online battles
//	0x1EA8  u32      online races (all)
//	0x2128  u8[200]  unlock flags (1 = unlocked) — karts/wheels/gliders/characters/…
const (
	mk8Magic            = "SUTC"
	mk8SubMagicOffset   = 0x48
	mk8OffCoins         = 0x195C
	mk8OffRaceRating    = 0x1E94 // VR
	mk8OffBattleRating  = 0x1E98 // BR
	mk8OffOnlineRaces   = 0x1EA8
	mk8UnlockFlagOffset = 0x2128
	mk8UnlockFlagCount  = 200
)

// saveParsed: GET /api/save/<titleId>/parsed — best-effort content summary of one cloud save.
func (s *server) saveParsed(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusForbidden, "Indisponible pour les profils invités.")
		return
	}

	titleID := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/save/"), "/parsed"))
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	p := filepath.Join(saveDir, strconv.FormatUint(acct.PID, 10), titleID+".bin")
	blob, err := os.ReadFile(p)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"titleId": titleID, "exists": false, "fields": []saveField{}})
		return
	}

	files := unzipSave(blob)
	fields := parseSaveFields(canonTitleID(titleID), files, saveLang(r.URL.Query().Get("lang")))

	writeJSON(w, http.StatusOK, map[string]any{
		"titleId": titleID,
		"exists":  true,
		"fields":  fields,
	})
}

// unzipSave reads the save zip into memory as name -> bytes. Bounded so a malformed/huge blob
// can't exhaust memory (real Switch saves are small; the PUT path already caps at 64 MiB).
func unzipSave(blob []byte) map[string][]byte {
	out := map[string][]byte{}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		return out
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		out[strings.ToLower(f.Name)] = b
	}
	return out
}

// saveFile returns the first entry whose base name matches (case-insensitive), regardless of
// the sub-directory it sits in inside the zip.
func saveFile(files map[string][]byte, base string) []byte {
	base = strings.ToLower(base)
	for name, b := range files {
		if strings.ToLower(filepath.Base(name)) == base {
			return b
		}
	}
	return nil
}

// parseSaveFields dispatches on the canonical title id. Only games with a PROVEN parser
// return fields; everything else returns an empty slice (honest "no preview" on the site).
func parseSaveFields(canonTitle string, files map[string][]byte, lang string) []saveField {
	switch canonTitle {
	case "0100152000022000": // Mario Kart 8 Deluxe
		if ud := saveFile(files, "userdata.dat"); ud != nil {
			return mk8Fields(ud)
		}
	case "0100f8f0000a2000": // Splatoon 2 (encrypted save.dat — decoded first)
		if sd := saveFile(files, "save.dat"); sd != nil {
			if body := decodeS2Save(sd); body != nil {
				return s2Fields(body, lang)
			}
		}
	}
	return []saveField{}
}

// mk8Fields reads MK8DX online/progression stats from userdata.dat. Both "SUTC" magics are
// validated before any offset is trusted, and each value is range-checked, so a wrong/renamed
// file can never surface garbage.
func mk8Fields(ud []byte) []saveField {
	if len(ud) < mk8UnlockFlagOffset+mk8UnlockFlagCount ||
		string(ud[0:4]) != mk8Magic ||
		len(ud) < mk8SubMagicOffset+4 || string(ud[mk8SubMagicOffset:mk8SubMagicOffset+4]) != mk8Magic {
		return []saveField{}
	}
	u32 := func(off int) (uint32, bool) {
		if off < 0 || off+4 > len(ud) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(ud[off : off+4]), true
	}
	fields := []saveField{}
	add := func(key string, off int, max uint32) {
		if v, ok := u32(off); ok && v <= max {
			fields = append(fields, saveField{K: key, V: strconv.FormatUint(uint64(v), 10)})
		}
	}
	add("mk8Vr", mk8OffRaceRating, 99999)      // VR (Race Rating)
	add("mk8Br", mk8OffBattleRating, 99999)    // BR (Battle Rating)
	add("mk8Races", mk8OffOnlineRaces, 999999) // online races
	add("mk8Coins", mk8OffCoins, 99999)

	// Unlocked items — proven 0x2128 flag table.
	n := 0
	for i := 0; i < mk8UnlockFlagCount; i++ {
		if ud[mk8UnlockFlagOffset+i] != 0 {
			n++
		}
	}
	fields = append(fields, saveField{K: "mk8Unlocked", V: strconv.Itoa(n) + " / " + strconv.Itoa(mk8UnlockFlagCount)})
	return fields
}

package main

// [Nextendo] Private map-rotation API for the community Splatoon 2 rotation site.
//
// This does NOT reflect the game's real in-game rotation (that is computed by the
// S2 schedule algorithm from the BCAT byaml seeds). It serves a DETERMINISTIC,
// FICTIONAL rotation: seeded per 2-hour slot so the same slot always returns the
// same stages/rule (stable across refreshes) and it advances every 2 hours — plus
// Salmon Run on a longer window. All modes are covered.
//
// GET /api/splatoon2/rotation[?key=…]  → JSON {updated_at, regular[], ranked[], league[], salmon_run[]}
// "key" is checked only when NEXTENDO_ROTATION_KEY is set (fail-open otherwise),
// so the site can be pointed at it immediately and locked later.

import (
	"net/http"
	"os"
	"time"
)

var rotStages = []string{
	"The Reef", "Musselforge Fitness", "Starfish Mainstage", "Sturgeon Shipyard",
	"Inkblot Art Academy", "Humpback Pump Track", "Manta Maria", "Port Mackerel",
	"Moray Towers", "Snapper Canal", "Kelp Dome", "Blackbelly Skatepark",
	"Shellendorf Institute", "MakoMart", "Walleye Warehouse", "Arowana Mall",
	"Camp Triggerfish", "Piranha Pit", "Goby Arena", "New Albacore Hotel",
	"Wahoo World", "Ancho-V Games", "Skipper Pavilion",
}

// splatoon2.ink SplatNet stage renders (id-aligned with rotStages).
var rotStageHash = []string{
	"98baf21c0366ce6e03299e2326fe6d27a7582dce", "83acec875a5bb19418d7b87d5df4ba1e38ceac66",
	"187987856bf575c4155d021cb511034931d06d24", "bc794e337900afd763f8a88359f83df5679ddf12",
	"5c030a505ee57c889d3e5268a4b10c1f1f37880a", "fc23fedca2dfbbd8707a14606d719a4004403d13",
	"070d7ee287fdf3c5df02411950c2a1ce5b238746", "0907fc7dc325836a94d385919fe01dc13848612a",
	"96fd8c0492331a30e60a217c94fd1d4c73a966cc", "8c95053b3043e163cbfaaf1ec1e5f3eb770e5e07",
	"a12e4bf9f871677a5f3735d421317fbbf09e1a78", "758338859615898a59e93b84f7e1ca670f75e865",
	"23259c80272f45cea2d5c9e60bc0cedb6ce29e46", "d9f0f6c330aaa3b975e572637b00c4c0b6b89f7d",
	"65c99da154295109d6fe067005f194f681762f8c", "dcf332bdcc80f566f3ae59c1c3a29bc6312d0ba8",
	"e4c4800be9fff23112334b193abb0fdf36e05933", "828e49a8414a4bbc0a5da3e61454ab148a9f4063",
	"8cab733d543efc9dd561bfcc9edac52594e62522", "98a7d7a4009fae9fb7479554535425a5a604e88e",
	"555c356487ac3edb0088c416e8045576c6b37fcc", "1430e5ac7ae9396a126078eeab824a186b490b5a",
	"132327c819abf2bd44d0adc0f4a21aad9cc84bb2",
}

func rotStageImage(id int) string {
	if id < 0 || id >= len(rotStageHash) {
		return ""
	}
	return "https://splatoon2.ink/assets/splatnet/images/stage/" + rotStageHash[id] + ".png"
}

type rotRule struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

var rotRankedRules = []rotRule{
	{"splat_zones", "Splat Zones"}, {"tower_control", "Tower Control"},
	{"rainmaker", "Rainmaker"}, {"clam_blitz", "Clam Blitz"},
}
var rotTurf = rotRule{"turf_war", "Turf War"}

var rotSalmonStages = []struct {
	ID   int
	Name string
}{
	{5000, "Spawning Grounds"}, {5001, "Marooner's Bay"}, {5002, "Lost Outpost"},
	{5003, "Salmonid Smokeyard"}, {5004, "Ruins of Ark Polaris"},
}
var rotSalmonWeapons = []string{
	"Splattershot", "Splat Roller", "Splat Charger", "Slosher", "Splat Dualies",
	"Aerospray MG", "Blaster", "Heavy Splatling", "Tri-Slosher", "Flingza Roller",
	"L-3 Nozzlenose", "Bamboozler 14 Mk I", "Splat Brella", "Rapid Blaster",
}

// splitmix64 → deterministic per-seed RNG.
func rotRand(seed uint64) func() uint64 {
	s := seed
	return func() uint64 {
		s += 0x9E3779B97F4A7C15
		z := s
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
}

// pick n distinct indices in [0,max) from a seed (Fisher–Yates on a small pool).
func rotPick(seed uint64, max, n int) []int {
	r := rotRand(seed)
	pool := make([]int, max)
	for i := range pool {
		pool[i] = i
	}
	for i := max - 1; i > 0; i-- {
		j := int(r() % uint64(i+1))
		pool[i], pool[j] = pool[j], pool[i]
	}
	return pool[:n]
}

type rotStageOut struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
}
type rotSlot struct {
	StartTime int64         `json:"start_time"`
	EndTime   int64         `json:"end_time"`
	Rule      rotRule       `json:"rule"`
	Stages    []rotStageOut `json:"stages"`
}
type rotSalmonSlot struct {
	StartTime int64       `json:"start_time"`
	EndTime   int64       `json:"end_time"`
	Stage     rotStageOut `json:"stage"`
	Weapons   []string    `json:"weapons"`
}

func rotStageObj(id int) rotStageOut {
	return rotStageOut{ID: id, Name: rotStages[id], Image: rotStageImage(id)}
}

// modeSalt keeps regular/ranked/league independent while staying per-slot deterministic.
func rotVsSlots(now time.Time, salt uint64, ranked bool) []rotSlot {
	const period = int64(2 * 3600)
	base := now.Unix() - (now.Unix() % period)
	out := make([]rotSlot, 0, 12)
	for i := int64(0); i < 12; i++ {
		start := base + i*period
		slot := uint64(start/period)*1000003 + salt
		st := rotPick(slot, len(rotStages), 2)
		rule := rotTurf
		if ranked {
			rule = rotRankedRules[(rotRand(slot+7)()>>3)%uint64(len(rotRankedRules))]
		}
		out = append(out, rotSlot{
			StartTime: start, EndTime: start + period, Rule: rule,
			Stages: []rotStageOut{rotStageObj(st[0]), rotStageObj(st[1])},
		})
	}
	return out
}

func rotSalmonSlots(now time.Time) []rotSalmonSlot {
	const period = int64(40 * 3600) // ~game-like Salmon Run window
	base := now.Unix() - (now.Unix() % period)
	out := make([]rotSalmonSlot, 0, 5)
	for i := int64(0); i < 5; i++ {
		start := base + i*period
		slot := uint64(start/period)*7919 + 55
		r := rotRand(slot)
		sr := rotSalmonStages[r()%uint64(len(rotSalmonStages))]
		weps := make([]string, 4)
		for k := range weps {
			weps[k] = rotSalmonWeapons[r()%uint64(len(rotSalmonWeapons))]
		}
		out = append(out, rotSalmonSlot{
			StartTime: start, EndTime: start + period,
			Stage:   rotStageOut{ID: sr.ID, Name: sr.Name},
			Weapons: weps,
		})
	}
	return out
}

// splatRotation serves the fictional rotation for all modes. GET /api/splatoon2/rotation
func (s *server) splatRotation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if key := os.Getenv("NEXTENDO_ROTATION_KEY"); key != "" && r.URL.Query().Get("key") != key {
		writeErr(w, http.StatusForbidden, "clé requise")
		return
	}
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, map[string]any{
		"updated_at":  now.Format(time.RFC3339),
		"note":        "Rotation fictive et déterministe (créneaux 2h). Non affiliée à Nintendo.",
		"regular":     rotVsSlots(now, 1, false),
		"ranked":      rotVsSlots(now, 2, true),
		"league":      rotVsSlots(now, 3, true),
		"salmon_run":  rotSalmonSlots(now),
	})
}

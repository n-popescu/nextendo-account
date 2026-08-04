package main

// [Nextendo] Favoris de mods GameBanana, stockés PAR COMPTE dans accounts.json et synchronisés
// entre les PC de l'utilisateur. Le magasin de mods de l'émulateur les lit/écrit via ces
// endpoints, authentifiés au jeton NEX du compte (accountFromBearer). Ainsi on retrouve les mods
// qu'on aime d'un PC à l'autre.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const maxModFavorites = 500

type ModFavorite struct {
	ModID        int64     `json:"mod_id"`
	GameID       int64     `json:"game_id,omitempty"`
	Name         string    `json:"name,omitempty"`
	Author       string    `json:"author,omitempty"`
	Category     string    `json:"category,omitempty"`
	ThumbnailURL string    `json:"thumbnail_url,omitempty"`
	ProfileURL   string    `json:"profile_url,omitempty"`
	AddedAt      time.Time `json:"added_at"`
}

func clampStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AddModFavorite ajoute (ou rafraîchit les métadonnées d') un favori. Idempotent par ModID.
func (s *jsonStore) AddModFavorite(id int64, fav ModFavorite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	for i := range a.ModFavorites {
		if a.ModFavorites[i].ModID == fav.ModID {
			fav.AddedAt = a.ModFavorites[i].AddedAt // garde l'ancienneté d'origine
			a.ModFavorites[i] = fav                 // rafraîchit nom/miniature/etc.
			return s.persist()
		}
	}
	if len(a.ModFavorites) >= maxModFavorites {
		return errors.New("trop de favoris")
	}
	a.ModFavorites = append(a.ModFavorites, fav)
	return s.persist()
}

func (s *jsonStore) RemoveModFavorite(id int64, modID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	out := a.ModFavorites[:0]
	for _, f := range a.ModFavorites {
		if f.ModID != modID {
			out = append(out, f)
		}
	}
	a.ModFavorites = out
	return s.persist()
}

func (s *jsonStore) ListModFavorites(id int64, gameID int64) ([]ModFavorite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]ModFavorite, 0, len(a.ModFavorites))
	for _, f := range a.ModFavorites {
		if gameID == 0 || f.GameID == gameID {
			out = append(out, f)
		}
	}
	return out, nil
}

// modFavorites : GET liste (?game_id=N pour filtrer), POST ajoute/rafraîchit. Authentifié.
func (s *server) modFavorites(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		var gameID int64
		if g := r.URL.Query().Get("game_id"); g != "" {
			gameID, _ = strconv.ParseInt(g, 10, 64)
		}
		favs, err := s.store.ListModFavorites(acct.ID, gameID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"favorites": favs})

	case http.MethodPost:
		var in ModFavorite
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.ModID == 0 {
			writeErr(w, http.StatusBadRequest, "JSON invalide")
			return
		}
		// Bornage : ne pas laisser stocker des champs arbitrairement longs dans accounts.json.
		in.Name = clampStr(in.Name, 200)
		in.Author = clampStr(in.Author, 100)
		in.Category = clampStr(in.Category, 100)
		in.ThumbnailURL = clampStr(in.ThumbnailURL, 400)
		in.ProfileURL = clampStr(in.ProfileURL, 400)
		in.AddedAt = time.Now().UTC()
		if err := s.store.AddModFavorite(acct.ID, in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "méthode non permise")
	}
}

// modFavoriteRemove : POST {mod_id} retire un favori. Authentifié.
func (s *server) modFavoriteRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct {
		ModID int64 `json:"mod_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.ModID == 0 {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if err := s.store.RemoveModFavorite(acct.ID, in.ModID); err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

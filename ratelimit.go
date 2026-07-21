package main

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// Limitation de débit sur les chemins d'authentification.
//
// Il n'y en avait AUCUNE : /api/login acceptait un nombre illimité d'essais de mot de passe,
// /api/forgot permettait d'inonder n'importe quelle adresse de mails de réinitialisation (et
// de brûler la réputation SMTP du domaine), et /api/register d'créer des comptes en masse —
// chaque création réécrivant l'intégralité de accounts.json.
//
// Fenêtre glissante par clé (IP, ou IP+compte). Volontairement simple et en mémoire : le
// service est mono-instance, et l'objectif est de casser l'automatisation, pas de compter juste.

type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, limit: limit, window: window}
}

// allow enregistre une tentative et dit si elle est permise.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if now.Sub(t) < rl.window {
			kept = append(kept, t)
		}
	}
	// purge opportuniste : sans elle la map grossit indéfiniment (fuite mémoire).
	if len(kept) == 0 {
		delete(rl.hits, key)
	} else {
		rl.hits[key] = kept
	}
	if len(kept) >= rl.limit {
		return false
	}
	rl.hits[key] = append(rl.hits[key], now)
	return true
}

var (
	// 10 tentatives de connexion par IP et par 5 min : large pour un humain qui se trompe,
	// dérisoire pour une attaque par force brute.
	rlLogin = newRateLimiter(10, 5*time.Minute)
	// 3 demandes de réinitialisation par IP et par heure (anti mail-bombing).
	rlForgot = newRateLimiter(3, time.Hour)
	// 5 créations de compte par IP et par heure.
	rlRegister = newRateLimiter(5, time.Hour)
)

// rateGuard applique la limite et répond 429 le cas échéant. true = la requête peut continuer.
func rateGuard(w http.ResponseWriter, r *http.Request, rl *rateLimiter, what string) bool {
	ip := clientIP(r)
	if rl.allow(ip) {
		return true
	}
	log.Printf("[rate-limit] %s : trop de tentatives depuis %s", what, ip)
	w.Header().Set("Retry-After", "300")
	writeErr(w, http.StatusTooManyRequests, "Trop de tentatives. Réessaie dans quelques minutes.")
	return false
}

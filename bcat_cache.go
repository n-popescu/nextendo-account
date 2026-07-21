package main

// Sert le save "delivery-cache" BCAT d'un titre au homebrew Nextendo, VERBATIM depuis un
// bundle de cache (bcat_store/<titleId>.cache.zip). Un tel cache contient, en plus des
// byaml, des fichiers de tete que S2 EXIGE pour accepter le cache :
//   directories.meta · etag.bin · list.msgpack · na_required · directories/<topic>/files.meta
//   · directories/<topic>/files/<payload>  (+ un dossier "dummy")
// On relaie donc l'arbre TEL QUEL (aucun calcul de digest cote serveur) -> l'install ecrit le
// cache attendu -> S2 l'accepte. passphrase.bin est cree par S2 (exclu, preserve
// par le homebrew) ; .nx_save_meta.bin est un artefact JKSV (exclu).
//
// Bundle "NXBC" : "NXBC" | u32 count | count * [ u16 pathLen | path | u32 dataLen | data ]
// (path = chemin save-relatif, ex "directories/vsdata/files/VSSetting_0.byaml").

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const bcatBundleMagic = "NXBC"

// Garde-fous du bundle. Le client homebrew concatène AVEUGLÉMENT chaque chemin qu'on lui envoie
// au dossier de sauvegarde du jeu (audit path-traversal). Le serveur est, dans son
// modèle de confiance, la seule autorité — il doit donc GARANTIR qu'il n'émet jamais un chemin
// capable de sortir de l'arbre save, même si le cache source (bcat_store/<titleId>.cache.zip) est
// un jour corrompu ou altéré. On échoue FERMÉ : un seul chemin suspect refuse tout le bundle
// plutôt que d'en livrer un partiel (qu'un cache BCAT ne contient de toute façon jamais).
const (
	bcatMaxPathLen = 512
	bcatMaxEntries = 20000
)

type bcatBlob struct {
	path string
	data []byte
}

var bcatSkip = map[string]bool{"passphrase.bin": true, ".nx_save_meta.bin": true}

// safeBcatPath rejette tout chemin capable d'échapper à l'arbre de sauvegarde : segment "..",
// chemin absolu, lettre de lecteur / flux ADS (":"), antislash résiduel, octet nul, ou longueur
// aberrante. p est déjà débarrassé de son "/" initial et normalisé en "/" par l'appelant.
func safeBcatPath(p string) bool {
	if p == "" || len(p) > bcatMaxPathLen {
		return false
	}
	if strings.ContainsAny(p, ":\\\x00") || strings.HasPrefix(p, "/") {
		return false
	}
	// path.Clean résout les "." et ".." : si le résultat s'échappe ou diffère, on refuse.
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// buildBcatBundle lit bcat_store/<titleId>.cache.zip et renvoie le bundle NXBC (relais verbatim).
func buildBcatBundle(titleID string) ([]byte, error) {
	zr, err := zip.OpenReader(filepath.Join(bcatDir, titleID+".cache.zip"))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var blobs []bcatBlob
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		p := strings.ReplaceAll(strings.TrimPrefix(f.Name, "/"), "\\", "/")
		if p == "" || bcatSkip[path.Base(p)] {
			continue
		}
		// Ne JAMAIS relayer un chemin capable de sortir de l'arbre save. Un cache BCAT valide
		// n'en contient pas ; si on en voit un, le cache est corrompu ou piégé -> on refuse tout.
		if !safeBcatPath(p) {
			return nil, fmt.Errorf("bcat: chemin refusé (path traversal) dans %s.cache.zip : %q", titleID, p)
		}
		if len(blobs) >= bcatMaxEntries {
			return nil, fmt.Errorf("bcat: %s.cache.zip dépasse %d entrées", titleID, bcatMaxEntries)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, bcatBlob{path: p, data: data})
	}
	// Ordre deterministe (les dossiers parents sont crees a la volee cote .nro, l'ordre importe peu).
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].path < blobs[j].path })

	var out bytes.Buffer
	out.WriteString(bcatBundleMagic)
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(blobs)))
	for _, b := range blobs {
		_ = binary.Write(&out, binary.LittleEndian, uint16(len(b.path)))
		out.WriteString(b.path)
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(b.data)))
		out.Write(b.data)
	}
	return out.Bytes(), nil
}

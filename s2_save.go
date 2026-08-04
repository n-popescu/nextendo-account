package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
	"strconv"
)

// [Nextendo] Splatoon 2 cloud-save reader.
//
// S2's save.dat is NOT plaintext like MK8DX: it is version-8 ENCODED — AES-CBC over the whole
// body, wrapped in two block-shuffle passes whose blocks are themselves AES-encrypted, keyed by
// a bespoke PRNG (SeedRand) + lookup table, and MAC'd. This is a straight port of khang06's
// effective-spoon decoder, verified against a real save (read Level 41 / equipped weapon id 2 =
// "Marqueur lourd 7", matching the game). Once decoded we read a few proven struct offsets
// (SaveDataVss: Level/Stars/ranks; SaveDataCmn: equipped weapon).

const (
	s2Header   = 0x10
	s2Footer   = 0x30
	s2BodyV8   = 0x88D50 // decoded/encoded body size for save versions 7/8
	s2FileV8   = 0x88D90 // full encoded file size for versions 7/8
	s2VssOff   = 0x2B210 // SaveDataVss::Section start within the body (after SaveDataCmn)
	s2WeaponAt = 0x14    // SaveDataCmn EquippedWeapon.Main (after 5×u32 model ids)

	// WeaponInventory[0x100] of HaveWeapon (0x130 each), right after EquippedWeapon+pad.
	// Each entry: Main u32 @0x00, InkTurfed u32 @0x0C. Most-inked = the player's main weapon.
	s2InvOff    = 0x28
	s2InvStride = 0x130
	s2InvCount  = 0x100

	// SaveDataStats section (after Cmn+Vss+Local+Msn+Shop+Coop+Fest). Not RE'd by effective-spoon,
	// but the total-battles counter at +0x540 was confirmed against the player's in-game record.
	s2StatsOff     = 0x4839C
	s2StatsBattles = 0x540
)

// --- SeedRand: the save's bespoke PRNG (effective-spoon SeedRand) ---

type s2Rand struct{ s [4]uint32 }

func s2RandSeed(seed uint32) *s2Rand {
	r := &s2Rand{}
	for i := 0; i < 4; i++ {
		r.s[i] = 0x6C078965*(seed^(seed>>30)) + uint32(i) + 1
		seed = r.s[i]
	}
	return r
}

func s2RandState(st [4]uint32) *s2Rand { return &s2Rand{s: st} }

func (r *s2Rand) u32() uint32 {
	a := r.s[0] ^ (r.s[0] << 11)
	b := r.s[3]
	c := a ^ (a >> 8) ^ b ^ (b >> 19)
	r.s[0], r.s[1], r.s[2] = r.s[1], r.s[2], r.s[3]
	r.s[3] = c
	return c
}

func (r *s2Rand) u64() uint64 {
	a := r.s[1]
	b := r.s[0] ^ (r.s[0] << 11)
	c := r.s[3]
	r.s[0] = r.s[2]
	r.s[1] = c
	d := b ^ (b >> 8) ^ c
	e := d ^ (c >> 19)
	aa := a ^ (a << 11)
	f := a ^ (a << 11) ^ (aa >> 8) ^ e ^ (d >> 19)
	r.s[2] = e
	r.s[3] = f
	return uint64(f) | (uint64(e) << 32)
}

func s2GetKey(r *s2Rand) []byte {
	key := make([]byte, 16)
	for i := 0; i < 4; i++ {
		var k uint32
		for j := 0; j < 4; j++ {
			idx := r.u32() >> 26
			sh := (r.u32() >> 27) & 0x18
			k = (k << 8) | uint32((cryptTab7[idx]>>sh)&0xFF)
		}
		binary.LittleEndian.PutUint32(key[i*4:], k)
	}
	return key
}

func s2ReverseBits(v uint32) uint32 {
	v = ((v << 1) & 0xAAAAAAAA) | ((v >> 1) & 0x55555555)
	v = ((v << 2) & 0xCCCCCCCC) | ((v >> 2) & 0x33333333)
	v = ((v << 4) & 0xF0F0F0F0) | ((v >> 4) & 0x0F0F0F0F)
	v = ((v << 8) & 0xFF00FF00) | ((v >> 8) & 0x00FF00FF)
	v = ((v << 16) & 0xFFFF0000) | ((v >> 16) & 0x0000FFFF)
	return v
}

func s2AesCbcDecrypt(key, iv, data []byte) []byte {
	if len(iv) != 16 || len(data) == 0 || len(data)%16 != 0 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	ivc := make([]byte, 16)
	copy(ivc, iv)
	cipher.NewCBCDecrypter(block, ivc).CryptBlocks(out, data)
	return out
}

type s2ShuffleBlock struct{ size, unshuffled, shuffled int }

func s2GetShuffleBlocks(total int, seed uint32) []s2ShuffleBlock {
	r := s2RandSeed(seed)
	minb := total / 0x10
	maxb := minb * 2
	var sizes, uoffs []int
	cur := 0
	for total-cur > minb {
		if maxb > total-cur {
			maxb = total - cur
		}
		rnd := uint64(r.u32())
		a := (uint64((maxb-minb)&0xFFFFFFF0) + 1) * rnd
		bs := int(((a >> 32) + uint64(minb&0xFFFFFFF0)) & 0xFFFFFFF0)
		sizes = append(sizes, bs)
		uoffs = append(uoffs, cur)
		cur += bs
	}
	if total > cur {
		sizes = append(sizes, total-cur)
		uoffs = append(uoffs, cur)
	}
	idx := make([]int, len(sizes))
	for i := range idx {
		idx[i] = i
	}
	remaining := len(idx)
	for remaining > 1 {
		toI := remaining - 1
		fromI := int((uint64(remaining) * uint64(r.u32())) >> 32)
		idx[fromI], idx[toI] = idx[toI], idx[fromI]
		remaining--
	}
	out := make([]s2ShuffleBlock, 0, len(idx))
	curSh := 0
	for i := 0; i < len(idx); i++ {
		out = append(out, s2ShuffleBlock{sizes[idx[i]], uoffs[idx[i]], curSh})
		curSh += sizes[idx[i]]
	}
	return out
}

// s2Unshuffle reverses one shuffle pass (v8: every block is also AES-decrypted).
func s2Unshuffle(body []byte, crc uint32, isEncoded bool) []byte {
	total := len(body)
	seed := s2ReverseBits(crc)
	if !isEncoded {
		seed = ^seed
	}
	blocks := s2GetShuffleBlocks(total, seed)
	tmp := make([]byte, total)
	copy(tmp, body)
	dst := make([]byte, total)
	for _, blk := range blocks {
		if blk.size <= 0 || blk.shuffled+blk.size > total || blk.unshuffled+blk.size > total {
			return nil
		}
		brng := s2RandSeed(uint32(blk.size))
		iv := make([]byte, 16)
		binary.LittleEndian.PutUint64(iv[0:], brng.u64())
		binary.LittleEndian.PutUint64(iv[8:], brng.u64())
		key := s2GetKey(brng)
		dec := s2AesCbcDecrypt(key, iv, tmp[blk.shuffled:blk.shuffled+blk.size])
		if dec == nil {
			return nil
		}
		copy(dst[blk.unshuffled:blk.unshuffled+blk.size], dec)
	}
	return dst
}

// decodeS2Save turns an encoded (on-disk) Splatoon 2 save.dat into its decoded body, or nil.
func decodeS2Save(data []byte) (body []byte) {
	defer func() {
		if recover() != nil {
			body = nil
		}
	}()
	if len(data) != s2FileV8 {
		return nil // only version 7/8 (current S2) is handled
	}
	version := binary.LittleEndian.Uint32(data[0:4])
	if version != 7 && version != 8 {
		return nil
	}
	encHeader := data[:s2Header]
	encBody := make([]byte, s2BodyV8)
	copy(encBody, data[s2Header:s2Header+s2BodyV8])
	footer := data[s2Header+s2BodyV8:]
	iv := footer[:0x10]
	var keySeed [4]uint32
	for i := 0; i < 4; i++ {
		keySeed[i] = binary.LittleEndian.Uint32(footer[0x10+i*4:])
	}
	crc := binary.LittleEndian.Uint32(encHeader[0x8:])

	// 1) unshuffle the encoded body, 2) AES-CBC decrypt it, 3) unshuffle the decoded body.
	if encBody = s2Unshuffle(encBody, crc, true); encBody == nil {
		return nil
	}
	dec := s2AesCbcDecrypt(s2GetKey(s2RandState(keySeed)), iv, encBody)
	if dec == nil {
		return nil
	}
	if dec = s2Unshuffle(dec, crc, false); dec == nil {
		return nil
	}
	// Validation : le CRC du header (data[8:12]) est le CRC32 (IEEE) du body déchiffré. Un décodage
	// désaligné — save d'une AUTRE version de structure que celle visée, ou corrompue — ne matchera
	// pas. Sans ce contrôle, on servait des offsets tombant sur du garbage (niveaux 0xFFFFFFFF,
	// compteurs aberrants) : prouvé sur de vraies saves. On refuse plutôt que d'afficher du faux.
	if crc32.ChecksumIEEE(dec) != crc {
		return nil
	}
	return dec
}

// s2RankLabel maps the udemae tier index (C- .. S+) to its label. X is stored separately.
func s2RankLabel(v uint32) string {
	labels := []string{"C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+", "S", "S+"}
	if int(v) < len(labels) {
		return labels[v]
	}
	return ""
}

// s2Fields reads the display stats from a decoded Splatoon 2 body (weapon name in `lang`).
func s2Fields(body []byte, lang string) (fields []saveField) {
	defer func() {
		if recover() != nil {
			fields = []saveField{}
		}
	}()
	fields = []saveField{}
	if len(body) < s2VssOff+0x40 {
		return fields
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(body[off : off+4]) }

	// Level (+ star rank once maxed). Sanity-gated so a bad decode can't surface junk.
	lvl := u32(s2VssOff + 0x00)
	if lvl >= 1 && lvl <= 99 {
		v := strconv.FormatUint(uint64(lvl), 10)
		if stars := u32(s2VssOff + 0x08); stars >= 1 && stars <= 5 {
			v = "★" + strconv.FormatUint(uint64(stars), 10) + " · " + v
		}
		fields = append(fields, saveField{K: "s2Level", V: v})
	}

	// « Parties jouées » RETIRÉ : l'offset SaveDataStats (0x4839C) est VERSION-DÉPENDANT — cette
	// section tardive se décale entre versions de structure de save. Sur des décodages pourtant
	// validés par CRC, +0x540 donnait 222 (juste) pour l'un mais 33 M / 50 M pour d'autres. Tant
	// qu'on ne localise pas SaveDataStats par version (ou via un repère de section), on n'affiche
	// pas ce champ plutôt qu'un nombre faux. Level/arme/rangs (sections précoces Cmn/Vss) sont stables.

	// Favorite weapon = the one with the most ink turfed across the inventory (falls back to
	// the currently-equipped weapon if usage data is unreadable).
	fav := u32(s2WeaponAt)
	var bestInk uint32
	for i := 0; i < s2InvCount; i++ {
		base := s2InvOff + i*s2InvStride
		if base+0x10 > len(body) {
			break
		}
		if ink := u32(base + 0x0C); ink > bestInk {
			bestInk = ink
			fav = u32(base)
		}
	}
	if name := s2WeaponName(fav, lang); name != "" {
		fields = append(fields, saveField{K: "s2Weapon", V: name, Img: s2WeaponIcons[fav]})
	}

	// Ranked ranks (Splat Zones / Tower Control / Rainmaker / Clam Blitz).
	for _, rk := range []struct {
		k   string
		off int
	}{
		{"s2RankSz", s2VssOff + 0x24},
		{"s2RankTc", s2VssOff + 0x30},
		{"s2RankRm", s2VssOff + 0x18},
		{"s2RankCb", s2VssOff + 0x3C},
	} {
		if lbl := s2RankLabel(u32(rk.off)); lbl != "" {
			fields = append(fields, saveField{K: rk.k, V: lbl})
		}
	}
	return fields
}

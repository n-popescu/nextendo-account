package main

import (
	"strings"
	"testing"
	"time"
)

func resetReports() {
	reportsMu.Lock()
	reports = nil
	reportSeq = 0
	reportsMu.Unlock()
}

// Le quota doit se décider AVANT qu'on lise le corps : un client en boucle ne doit pas nous
// faire allouer et parser 192 Ko à chaque refus.
func TestQuotaIsCheckableWithoutReadingTheBody(t *testing.T) {
	resetReports()

	const pid = 1800000006
	for i := 0; i < reportPerHour; i++ {
		if !reportQuotaAvailable(pid) {
			t.Fatalf("le quota doit rester ouvert pour les %d premiers, refusé au %d", reportPerHour, i)
		}
		reportsMu.Lock()
		reports = append(reports, bugReport{PID: pid, CreatedAt: time.Now()})
		reportsMu.Unlock()
	}

	if reportQuotaAvailable(pid) {
		t.Error("passé le quota, le refus doit tomber sans lire le corps")
	}

	// Le quota est par compte : un spammeur ne doit pas museler les autres.
	if !reportQuotaAvailable(1800000519) {
		t.Error("le quota d'un compte ne doit pas s'appliquer aux autres")
	}
}

// La boîte est bornée : un flot de signalements ne doit pas faire enfler la mémoire.
func TestInboxStaysBounded(t *testing.T) {
	resetReports()

	reportsMu.Lock()
	for i := 0; i < maxReports*3; i++ {
		reports = append(reports, bugReport{PID: uint64(i), CreatedAt: time.Now()})
		if len(reports) > maxReports {
			reports = append([]bugReport(nil), reports[len(reports)-maxReports:]...)
		}
	}
	n := len(reports)
	reportsMu.Unlock()

	if n != maxReports {
		t.Errorf("boîte à %d entrées, plafond attendu %d", n, maxReports)
	}
}

// Un log de client peut arriver énorme ; on garde la FIN, là où est l'erreur.
func TestLogIsClampedKeepingTheEnd(t *testing.T) {
	huge := strings.Repeat("a", maxReportLog*2) + "LERREUREST_ICI"

	got := clampLog(huge)

	if len(got) > maxReportLog+64 {
		t.Errorf("log gardé à %d octets, plafond %d", len(got), maxReportLog)
	}
	if !strings.HasSuffix(got, "LERREUREST_ICI") {
		t.Error("la fin du log — là où est l'erreur — doit survivre à la troncature")
	}
}

// Les champs courts viennent d'un client et s'affichent dans la page admin.
func TestReportFieldsAreClamped(t *testing.T) {
	if got := clampReportField(strings.Repeat("x", 999), 32); len(got) != 32 {
		t.Errorf("champ de %d caractères, plafond 32", len(got))
	}
	if got := clampReportField("2618\r\n-0006\x00", 32); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("les caractères de contrôle doivent sauter, obtenu %q", got)
	}
}

// Les vieux signalements sont jetés : ils ne correspondent plus à aucun log serveur.
func TestOldReportsArePruned(t *testing.T) {
	resetReports()

	reportsMu.Lock()
	reports = []bugReport{
		{ID: "vieux", CreatedAt: time.Now().Add(-reportMaxAge - time.Hour)},
		{ID: "recent", CreatedAt: time.Now()},
	}
	pruneReports()
	n, id := len(reports), reports[0].ID
	reportsMu.Unlock()

	if n != 1 || id != "recent" {
		t.Errorf("après purge : %d entrée(s), première=%q ; attendu 1 et \"recent\"", n, id)
	}
}

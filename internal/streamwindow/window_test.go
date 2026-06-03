package streamwindow

import (
	"testing"
	"time"
)

func TestAllowedNowKathmanduWindow(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Kathmandu")
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	// 2026-06-03 10:00 in Kathmandu
	at := time.Date(2026, 6, 3, 10, 0, 0, 0, loc)
	ok, err := p.AllowedNow(at)
	if err != nil || !ok {
		t.Fatalf("expected allowed at 10:00, got ok=%v err=%v", ok, err)
	}
	// 16:00 outside window
	at2 := time.Date(2026, 6, 3, 16, 0, 0, 0, loc)
	ok2, err := p.AllowedNow(at2)
	if err != nil || ok2 {
		t.Fatalf("expected blocked at 16:00, got ok=%v err=%v", ok2, err)
	}
}

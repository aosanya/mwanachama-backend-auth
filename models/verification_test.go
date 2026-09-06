package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerificationStatusValues(t *testing.T) {
	cases := map[VerificationStatus]string{
		VerificationStatusUnverified: "unverified",
		VerificationStatusPending:    "pending",
		VerificationStatusVerified:   "verified",
		VerificationStatusRejected:   "rejected",
	}
	for status, want := range cases {
		if string(status) != want {
			t.Errorf("status = %q, want %q", status, want)
		}
	}
}

// Note is optional — a plain status change with no note attached (the
// common case) must not send an empty "note" key.
func TestVerificationRecordNoteOmittedWhenEmpty(t *testing.T) {
	r := VerificationRecord{MemberID: "m1", Status: VerificationStatusVerified, UpdatedAt: time.Unix(0, 0).UTC()}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := got["note"]; ok {
		t.Errorf("record with no note should omit the key: %s", b)
	}

	r.Note = "ID verified against national registry"
	b2, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal with note: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(b2, &got2); err != nil {
		t.Fatalf("Unmarshal with note: %v", err)
	}
	if v, ok := got2["note"]; !ok || v != r.Note {
		t.Errorf("record with note should carry it, got %v (present=%v): %s", v, ok, b2)
	}
}

func TestVerificationRecordStatusRoundTrips(t *testing.T) {
	for _, status := range []VerificationStatus{
		VerificationStatusUnverified, VerificationStatusPending,
		VerificationStatusVerified, VerificationStatusRejected,
	} {
		r := VerificationRecord{MemberID: "m1", Status: status}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var got VerificationRecord
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Status != status {
			t.Errorf("Status round-trip = %q, want %q", got.Status, status)
		}
	}
}

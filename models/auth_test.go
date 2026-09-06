package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestChallengeKindValues(t *testing.T) {
	cases := map[ChallengeKind]string{
		KindDevice:   "device",
		KindPhone:    "phone",
		KindRecovery: "recovery",
	}
	for kind, want := range cases {
		if string(kind) != want {
			t.Errorf("kind = %q, want %q", kind, want)
		}
	}
}

func TestDeviceJSONFields(t *testing.T) {
	d := Device{ID: "d1", MemberID: "m1", PublicKey: "pk", Name: "phone", CreatedAt: time.Unix(0, 0).UTC()}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"id", "member_id", "public_key", "name", "created_at"} {
		if _, ok := got[key]; !ok {
			t.Errorf("marshaled Device missing key %q: %s", key, b)
		}
	}
}

// Challenge is a discriminated union over device/phone/recovery flows — only
// the fields relevant to the kind in play should be set, and the omitted
// ones must not show up on the wire (a client should not see device_id on a
// phone challenge).
func TestChallengeOptionalFieldsOmittedWhenEmpty(t *testing.T) {
	c := Challenge{
		ID:        "c1",
		Kind:      KindPhone,
		Phone:     "+254700000000",
		Secret:    "123456",
		ExpiresAt: time.Unix(0, 0).UTC(),
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"device_id", "member_id"} {
		if _, ok := got[key]; ok {
			t.Errorf("unset %q should be omitted from a phone challenge: %s", key, b)
		}
	}
	if _, ok := got["phone"]; !ok {
		t.Errorf("set phone should be present: %s", b)
	}
}

// TestAuthAndOperatorLockAfterDoNotCollideInValue pins that the two renamed
// lock-out budgets (AuthLockAfter, OperatorLockAfter) still agree on the
// policy they both encode — one number for "somebody is guessing" — even
// though they had to gain distinct names to coexist in this package.
func TestAuthAndOperatorLockAfterDoNotCollideInValue(t *testing.T) {
	if AuthLockAfter != 5 {
		t.Errorf("AuthLockAfter = %d, want 5", AuthLockAfter)
	}
	if AuthLockAfter != OperatorLockAfter {
		t.Errorf("AuthLockAfter (%d) and OperatorLockAfter (%d) diverged — "+
			"one policy for 'somebody is guessing', not two numbers that drift",
			AuthLockAfter, OperatorLockAfter)
	}
}

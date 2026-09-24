package authz

import (
	"encoding/json"
	"os"
	"testing"
)

// claimVectors is testdata/claims.json: token claims and what they mean. The same
// file is embedded by hanzoai/datastore's IAM user directory tests, so this package
// and the warehouse read one statement of the predicates and cannot drift apart
// without one of the two suites failing.
type claimVectors struct {
	SuperadminKid string `json:"superadmin_kid"`
	Cases         []struct {
		Name       string          `json:"name"`
		Kid        string          `json:"kid"`
		Claims     json.RawMessage `json:"claims"`
		Org        string          `json:"org"`
		Program    bool            `json:"program"`
		Person     bool            `json:"person"`
		Superadmin bool            `json:"superadmin"`
		Sudo       bool            `json:"sudo"`
	} `json:"cases"`
}

func TestClaimVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var v claimVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.SuperadminKid == "" || len(v.Cases) == 0 {
		t.Fatal("testdata/claims.json names no superadmin_kid or no cases")
	}

	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var c Claims
			if err := json.Unmarshal(tc.Claims, &c); err != nil {
				t.Fatal(err)
			}
			if got := c.Home(); got != tc.Org {
				t.Errorf("Home() = %q, want %q", got, tc.Org)
			}
			if got := c.Program(); got != tc.Program {
				t.Errorf("Program() = %v, want %v", got, tc.Program)
			}
			if got := !c.Machine(); got != tc.Person {
				t.Errorf("!Machine() = %v, want %v", got, tc.Person)
			}
			if got := c.Sudo(); got != tc.Sudo {
				t.Errorf("Sudo() = %v, want %v", got, tc.Sudo)
			}

			// The warehouse's SuperAdmin, stated by the vector, is this package's
			// Sudo narrowed to the home org and the admin org's own signing key. It
			// may be narrower than Sudo and never wider.
			want := tc.Person && tc.Org == AdminOrg && tc.Kid == v.SuperadminKid
			if tc.Superadmin != want {
				t.Errorf("superadmin = %v, but person=%v org=%q kid=%q says %v", tc.Superadmin, tc.Person, tc.Org, tc.Kid, want)
			}
			if tc.Superadmin && !c.Sudo() {
				t.Error("the vector grants SuperAdmin where Sudo() refuses platform authority")
			}
		})
	}
}

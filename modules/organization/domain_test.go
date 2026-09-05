package organization

import "testing"

func TestCreateValidation(t *testing.T) {
	good := Create{Key: "ORG", Name: "Organization", IdempotencyKey: "create-org-001"}
	if good.Validate() != nil {
		t.Fatal("valid create denied")
	}
	for _, name := range []string{"", " leading", "trailing ", "new\nline", string([]byte{0xff})} {
		value := good
		value.Name = name
		if value.Validate() == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
	for _, key := range []string{"short", "with spaces!", "slash/key", string(make([]byte, 129))} {
		value := good
		value.IdempotencyKey = key
		if value.Validate() == nil {
			t.Fatal("invalid idempotency key accepted")
		}
	}
}
func TestTeamParentMustBeCanonicalID(t *testing.T) {
	value := CreateTeam{OrganizationID: "019ed5bf-0000-7000-8000-000000000001", Key: "TEAM", Name: "Team", IdempotencyKey: "team-create-001"}
	if value.Validate() != nil {
		t.Fatal("valid root team denied")
	}
	value.ParentTeamID = "not-an-id"
	if value.Validate() == nil {
		t.Fatal("invalid parent accepted")
	}
}

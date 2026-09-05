package project

import "testing"

func TestGeneralProjectCommandValidation(t *testing.T) {
	value := Create{OrganizationID: "019ed5bf-0000-7000-8000-000000000001", OwningTeamID: "019ed5bf-0000-7000-8000-000000000002", Key: "PROJ", Title: "Project", Purpose: "General work", IdempotencyKey: "project-create-001"}
	if value.Validate() != nil {
		t.Fatal("valid project denied")
	}
	value.OwningTeamID = ""
	if value.Validate() == nil {
		t.Fatal("missing accountable team accepted")
	}
}

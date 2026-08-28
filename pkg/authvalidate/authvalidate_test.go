package authvalidate

import (
	"strings"
	"testing"
)

type request struct {
	Email string `binding:"required,email"`
	Name  string `binding:"required,min=3,max=5"`
	Note  string `binding:"omitempty,min=2"`
}

func TestValidateRetainsBindingSemanticsAndMessages(t *testing.T) {
	if err := Validate(&request{Email: "a@b.test", Name: "Nick"}); err != nil {
		t.Fatal(err)
	}
	err := Validate(&request{Email: "not-an-email", Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "'email' tag") || !strings.Contains(err.Error(), "'min' tag") {
		t.Fatalf("error = %v", err)
	}
}

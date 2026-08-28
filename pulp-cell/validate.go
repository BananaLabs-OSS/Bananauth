package main

import "github.com/bananalabs-oss/bananauth/pkg/authvalidate"

// validateRequest retains the established cell-local call surface while the
// reusable validation behavior lives in the stateless root library.
func validateRequest(value any) error { return authvalidate.Validate(value) }

package govalidator

import (
	"fmt"
	"regexp"
)

type validateError struct {
	str 	string
}

func newError(str string) error {
	return &validateError{str}
}

func newErrorf(format string, args ...interface{}) error {
	return &validateError{fmt.Sprintf(format, args...)}
}

func (e * validateError) Error() string {
	return e.str
}

// IsVarName validates the passed string has the correct length and characters for the approved set
func IsVarName(str string, min, max int) (bool, error) {
	if len(str) < min || len(str) > max {
		return false, newErrorf("Name must be between %d and %d in length", min, max)
	}
	isGood := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]+$`).MatchString
	if !isGood(str) {
		return false, newError("Name must start with alpha and contain only alphanum and '_'")
	}
	return true, nil
}

// IsPassword checks stirngs for length and for containing the specified number of charatcer groups
func IsPassword(str string, min, max, groups int) (bool, error) {
	if len(str) < min || len(str) > max {
		return false, newErrorf("Password must be between %d and %d in length", min, max)
	}
	hasNum := regexp.MustCompile(`.*[0-9]`).MatchString
	hasLower := regexp.MustCompile(`.*[a-zA-Z]`).MatchString
	hasUpper := regexp.MustCompile(`.*[a-zA-Z]`).MatchString
	hasSpecial := regexp.MustCompile(`.*[!"#$%&'()*+,\-./:;<=>?@[\\\]^_{|}~]`).MatchString

	count := 0
	if hasNum(str) 		{ count += 1 }
	if hasLower(str)	{ count += 1 }
	if hasUpper(str)	{ count += 1 }
	if hasSpecial(str)	{ count += 1 }

	if count < groups {
		return false, newErrorf("Password must contain %d charcter groups = lower case, upper case , numeric, and special characters", groups)
	}
	return true, nil
}

package govalidator

import (
	"testing"
	"fmt"
)

func TestIsPassword(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		pwd    string
		min 	int
		max 	int
		groups  int
		expected bool
	}{
		{"Redrum99", 8, 64, 3, true},
		{"Redrum99", 9, 64, 3, false},
		{"Redrum99", 8, 64, 4, false},
		{"Redrum999", 8, 8, 3, false},
		{"_Redrum99", 8, 64, 4, true},
		{"Redrum99{", 8, 64, 4, true},
		{"Red[rum99", 8, 64, 4, true},
		{"Red]rum99", 8, 64, 4, true},
	}
	for _, test := range tests {
		actual, err := IsPassword(test.pwd, test.min, test.max, test.groups)
		if actual != test.expected {
			t.Errorf("Expected IsPassword(%s, %d, %d, %d) to be %v, got %v", test.pwd, test.min, test.max, test.groups, test.expected, actual)
		}
		if err != nil {
			fmt.Printf("Expected IsPassword(%s, %d, %d, %d): ", test.pwd, test.min, test.max, test.groups)
			fmt.Println(err)
		}
	}
}

func TestIsVarName(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		min      int
		max      int
		expected bool
	}{
		{"Redrum99", 8, 64, true},
		{"Redrum99", 9, 64, false},
		{"99Redrum", 8, 64, false},
		{"_Redrum99", 8, 8, false},
		{"_Redrum99", 8, 64, false},
		{"Red rum99", 8, 64, false},
		{"Red_rum99", 8, 64, true},
		{"Red]rum99", 8, 64, false},
	}
	for _, test := range tests {
		actual, err := IsVarName(test.name, test.min, test.max)
		if actual != test.expected {
			t.Errorf("Expected IsVarName(%s, %d, %d) to be %v, got %v", test.name, test.min, test.max, test.expected, actual)
		}
		if err != nil {
			fmt.Printf("Expected IsVarName(%s, %d, %d): ", test.name, test.min, test.max)
			fmt.Println(err)
		}
	}
}

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

func TestIsRsaPub(t *testing.T) {
	var tests = []struct {
		rsastr 		string
		keylen 		int
		expected	bool
	}{
		{`fubar`, 2048, false},
		{`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvncDCeibmEkabJLmFec7x9y86RP6dIvkVxxbQoOJo06E+p7tH6vCmiGHKnuu
XwKYLq0DKUE3t/HHsNdowfD9+NH8caLzmXqGBx45/Dzxnwqz0qYq7idK+Qff34qrk/YFoU7498U1Ee7PkKb7/VE9BmMEcI3uoKbeXCbJRI
HoTp8bUXOpNTSUfwUNwJzbm2nsHo2xu6virKtAZLTsJFzTUmRd11MrWCvj59lWzt1/eIMN+ekjH8aXeLOOl54CL+kWp48C+V9BchyKCShZ
B7ucimFvjHTtuxziXZQRO7HlcsBOa0WwvDJnRnskdyoD31s4F4jpKEYBJNWTo63v6lUvbQIDAQAB`, 2048, true},
		{`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvncDCeibmEkabJLmFec7x9y86RP6dIvkVxxbQoOJo06E+p7tH6vCmiGHKnuu
XwKYLq0DKUE3t/HHsNdowfD9+NH8caLzmXqGBx45/Dzxnwqz0qYq7idK+Qff34qrk/YFoU7498U1Ee7PkKb7/VE9BmMEcI3uoKbeXCbJRI
HoTp8bUXOpNTSUfwUNwJzbm2nsHo2xu6virKtAZLTsJFzTUmRd11MrWCvj59lWzt1/eIMN+ekjH8aXeLOOl54CL+kWp48C+V9BchyKCShZ
B7ucimFvjHTtuxziXZQRO7HlcsBOa0WwvDJnRnskdyoD31s4F4jpKEYBJNWTo63v6lUvbQIDAQAB`, 1024, false},
		{`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvncDCeibmEkabJLmFec7
x9y86RP6dIvkVxxbQoOJo06E+p7tH6vCmiGHKnuuXwKYLq0DKUE3t/HHsNdowfD9
+NH8caLzmXqGBx45/Dzxnwqz0qYq7idK+Qff34qrk/YFoU7498U1Ee7PkKb7/VE9
BmMEcI3uoKbeXCbJRIHoTp8bUXOpNTSUfwUNwJzbm2nsHo2xu6virKtAZLTsJFzT
UmRd11MrWCvj59lWzt1/eIMN+ekjH8aXeLOOl54CL+kWp48C+V9BchyKCShZB7uc
imFvjHTtuxziXZQRO7HlcsBOa0WwvDJnRnskdyoD31s4F4jpKEYBJNWTo63v6lUv
bQIDAQAB
-----END PUBLIC KEY-----`, 2048, true},
		{`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvncDCeibmEkabJLmFec7
x9y86RP6dIvkVxxbQoOJo06E+p7tH6vCmiGHKnuuXwKYLq0DKUE3t/HHsNdowfD9
+NH8caLzmXqGBx45/Dzxnwqz0qYq7idK+Qff34qrk/YFoU7498U1Ee7PkKb7/VE9
BmMEcI3uoKbeXCbJRIHoTp8bUXOpNTSUfwUNwJzbm2nsHo2xu6virKtAZLTsJFzT
UmRd11MrWCvj59lWzt1/eIMN+ekjH8aXeLOOl54CL+kWp48C+V9BchyKCShZB7uc
imFvjHTtuxziXZQRO7HlcsBOa0WwvDJnRnskdyoD31s4F4jpKEYBJNWTo63v6lUv
bQIDAQAB
-----END PUBLIC KEY-----`, 4096, false},
	}
	for i, test := range tests {
		actual := IsRsaPub(test.rsastr, test.keylen)
		if actual != test.expected {
			t.Errorf("Expected IsRsaPub(%d, %d) to be %v, got %v", i, test.keylen, test.expected, actual)
		}
	}
}


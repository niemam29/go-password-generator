package generator

import (
	"github.com/dlclark/regexp2"
	"testing"
)

const PASS_LENGTH = 9

func TestGenerateLowSecurityPass(t *testing.T) {
	generatedPassword, _ := GeneratePass(LOW_SECURITY, PASS_LENGTH)
	if !(len(generatedPassword) == PASS_LENGTH) {
		t.Fatal("Password length should be", PASS_LENGTH, "instead of", len(generatedPassword))
	}
	onlyLowerCasePattern := regexp2.MustCompile("^[a-z]*$", regexp2.ECMAScript)
	isValid, _ := onlyLowerCasePattern.MatchString(generatedPassword)
	if !(isValid) {
		t.Fatal("Password violate security level requirements")
	}
}

func TestGenerateMediumSecurityPass(t *testing.T) {
	generatedPassword, _ := GeneratePass(MEDIUM_SECURITY, PASS_LENGTH)
	if !(len(generatedPassword) == PASS_LENGTH) {
		t.Fatal("Password length should be", PASS_LENGTH, "instead of", len(generatedPassword))
	}
	onlyLettersPattern := regexp2.MustCompile("^[A-Za-z]*$", regexp2.ECMAScript)
	lowerAndUpperPattern := regexp2.MustCompile("^(?=.*?[A-Z])(?=.*?[a-z]).{1,}$", regexp2.ECMAScript)
	isOnlyLetters, _ := onlyLettersPattern.MatchString(generatedPassword)
	isLowerAndUpper, _ := lowerAndUpperPattern.MatchString(generatedPassword)
	if !(isOnlyLetters && isLowerAndUpper) {
		t.Fatal("Password violate security level requirements")
	}
}

func TestGenerateHighSecurityPass(t *testing.T) {
	generatedPassword, _ := GeneratePass(HIGH_SECURITY, PASS_LENGTH)

	letterAndNumbersPattern := regexp2.MustCompile("^[A-Za-z0-9_-]*$", regexp2.ECMAScript)
	numberUpperLowerCasePattern := regexp2.MustCompile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{1,}$", regexp2.ECMAScript)
	isOnlyLetters, _ := letterAndNumbersPattern.MatchString(generatedPassword)
	isLowerAndUpper, _ := numberUpperLowerCasePattern.MatchString(generatedPassword)
	if !(isOnlyLetters && isLowerAndUpper) {
		t.Fatal("Password violate security level requirements")
	}

	if !(len(generatedPassword) == PASS_LENGTH) {
		t.Fatal("Password length should be", PASS_LENGTH, "instead of", len(generatedPassword))
	}
}

func TestGenerateUltraSecurityPass(t *testing.T) {
	generatedPassword, _ := GeneratePass(ULTRA_SECURITY, PASS_LENGTH)
	if !(len(generatedPassword) == PASS_LENGTH) {
		t.Fatal("Password length should be", PASS_LENGTH, "instead of", len(generatedPassword))
	}

	allCharactersPattern := regexp2.MustCompile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{1,}$", regexp2.ECMAScript)
	containAllCharacters, _ := allCharactersPattern.MatchString(generatedPassword)
	if !(containAllCharacters) {
		t.Fatal("Password violate security level requirements")
	}
}

func TestShouldNotAllowToGenerateToShortPassword(t *testing.T) {
	_, err := GeneratePass(ULTRA_SECURITY, 1)
	if !(err != nil) {
		t.Fatal("Should not allow to generate password shorter than 4 characters")
	}
}
func TestShouldNotAllowToGeneratePasswordWithInvalidSecurityLevel(t *testing.T) {
	_, err := GeneratePass(0, 1)
	if !(err != nil) {
		t.Fatal("Should not allow to generate password with invalid security level")
	}
}

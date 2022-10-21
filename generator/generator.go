package generator

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/dlclark/regexp2"

	"math/rand"
	"strings"
)

const (
	LOW_SECURITY    = 1
	MEDIUM_SECURITY = 2
	HIGH_SECURITY   = 3
	ULTRA_SECURITY  = 4
)

func GeneratePass(securityLevel int, passLength int) (string, error) {
	if passLength < 4 {
		return "", errors.New("PASS LENGTH SHOULD BE BIGGER THAN 4")
	}

	if securityLevel < 1 || securityLevel > 4 {
		return "", errors.New("SECURITY LEVEL INVALID")
	}

	var generatedSeed [8]byte
	crypto_rand.Read(generatedSeed[:])
	rand.Seed(int64(binary.LittleEndian.Uint64(generatedSeed[:])))

	specialChar := "#?!@$%^&*-"
	upCase := "ABCDEFGHIJKLMNOPQRSTUVXYZ"
	numbers := "0123456789"
	lowCase := "abcdefghijklmnopqrstuvxyz"
	var password strings.Builder

	for password.Len() < passLength {
		typeSpecificator := rand.Intn(securityLevel)
		switch typeSpecificator {
		case 0:
			password.WriteString(string(lowCase[rand.Intn(len(lowCase))]))
		case 1:
			password.WriteString(string(upCase[rand.Intn(len(upCase))]))
		case 2:
			password.WriteString(string(numbers[rand.Intn(len(numbers))]))
		case 3:
			password.WriteString(string(specialChar[rand.Intn(len(specialChar))]))
		}
	}

	var re *regexp2.Regexp

	switch securityLevel {
	case 1:
		re = regexp2.MustCompile(`(?=.*?[a-z]).{1,}$`, regexp2.ECMAScript)
	case 2:
		re = regexp2.MustCompile(`^(?=.*?[A-Z])(?=.*?[a-z]).{1,}$`, regexp2.ECMAScript)
	case 3:
		re = regexp2.MustCompile(`^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{1,}$`, regexp2.ECMAScript)
	case 4:
		re = regexp2.MustCompile(`^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{1,}$`, regexp2.ECMAScript)
	}

	matchString, _ := re.MatchString(password.String())
	if matchString {
		return password.String(), nil
	} else {
		return GeneratePass(securityLevel, passLength)
	}

}

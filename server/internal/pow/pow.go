package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math"
	"math/rand"
	"strconv"
	"strings"
)

const MAX_NONCE_COEFFICIENT = 3

func GenerateRandomData(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Failed to generate random data: %v", err)
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GetMaxNonceForOnlyZerosPrefix(prefixLength int) int64 {
	return int64(math.Pow(2, float64(4*prefixLength))) * MAX_NONCE_COEFFICIENT
}

func GetOnlyZerosPrefix(prefixLength int) string {
	return strings.Repeat("0", prefixLength)
}

func ValidatePoW(salt string, nonce int, prefix string) bool {
	data := salt + strconv.Itoa(nonce)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:len(prefix)] == prefix
}

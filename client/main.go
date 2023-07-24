package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	SERVER_ADDRESS = "server:8081"
)

func main() {
	conn, err := net.Dial("tcp", SERVER_ADDRESS)
	if err != nil {
		log.Fatalf("Failed to connect to the server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	err = handleProofOfWork(conn, reader)
	if err != nil {
		log.Fatalf("Failed to handle request: %v", err)
	}

	message, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read from connection: %v", err)
	}

	log.Println(message)
}

func handleProofOfWork(conn net.Conn, reader *bufio.Reader) error {
	salt, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return err
	}
	salt = strings.TrimSpace(salt)

	prefix, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return err
	}
	prefix = strings.TrimSpace(prefix)

	maxNonceStr, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return err
	}
	maxNonceStr = strings.TrimSpace(maxNonceStr)

	maxNonce, err := strconv.Atoi(maxNonceStr)
	if err != nil {
		log.Printf("Failed to parse maxNonce: %v", err)
		return err
	}

	nonce := computePoW(salt, prefix, maxNonce)
	_, err = conn.Write([]byte(fmt.Sprintf("%d\n", nonce)))
	if err != nil {
		log.Printf("Failed to write to connection: %v", err)
		return err
	}
	return nil
}

func computePoW(salt, prefix string, maxNonce int) int {
	for nonce := 0; nonce < maxNonce; nonce++ {
		data := salt + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		if hex.EncodeToString(hash[:])[:len(prefix)] == prefix {
			return nonce
		}
	}
	return -1
}

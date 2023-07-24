package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"server/internal/pow"
	"server/internal/quotes"
)

const (
	POW_PREFIX_ZEROS_COUNT = 5
	SALT_LENGTH            = 16
	TIMEOUT                = 30 * time.Second
)

var ErrPOWFailed = errors.New("PoW failed")
var ErrIncorrectNonce = errors.New("Incorrect nonce")

func main() {
	rand.Seed(time.Now().UnixNano())

	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			return
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
		}
	}()

	err := conn.SetReadDeadline(time.Now().Add(TIMEOUT))
	if err != nil {
		log.Printf("Failed to set read deadline: %v", err)
		return
	}

	err = conn.SetWriteDeadline(time.Now().Add(TIMEOUT))
	if err != nil {
		log.Printf("Failed to set write deadline: %v", err)
		return
	}

	err = handleProofOfWork(conn)
	if err != nil {
		log.Printf("Failed to handle proof of work: %v", err)
		return
	}

	_, err = conn.Write([]byte(quotes.GetQuote() + "\n"))
	if err != nil {
		log.Printf("Failed to write to connection: %v", err)
	}
}

func handleProofOfWork(conn net.Conn) error {
	salt, err := pow.GenerateRandomData(SALT_LENGTH)
	if err != nil {
		log.Printf("Failed to generate salt: %v", err)
		return err
	}
	maxNonce := pow.GetMaxNonceForOnlyZerosPrefix(POW_PREFIX_ZEROS_COUNT)
	powPrefix := pow.GetOnlyZerosPrefix(POW_PREFIX_ZEROS_COUNT)

	_, err = conn.Write([]byte(fmt.Sprintf("%s\n%s\n%d\n", salt, powPrefix, maxNonce)))
	if err != nil {
		log.Printf("Failed to send salt: %v", err)
		return err
	}

	buffer, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return err
	}

	nonceStr := strings.TrimSpace(buffer)
	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		log.Printf("Failed to parse nonce: %v", err)
		return err
	}
	if nonce < 0 || nonce > int(maxNonce) {
		log.Printf("%s: %s", ErrIncorrectNonce.Error(), nonceStr)
		_, writeErr := conn.Write([]byte(ErrIncorrectNonce.Error() + "\n"))
		if writeErr != nil {
			log.Printf("Failed to write to connection: %v", writeErr)
			return err
		}
		return ErrIncorrectNonce
	}

	if pow.ValidatePoW(salt, nonce, powPrefix) == false {
		_, err := conn.Write([]byte(ErrPOWFailed.Error() + "\n"))
		if err != nil {
			log.Printf("Failed to write to connection: %v", err)
			return err
		}
		return ErrPOWFailed
	}

	log.Println("PoW succeeded, nonce:", nonceStr)

	return nil
}

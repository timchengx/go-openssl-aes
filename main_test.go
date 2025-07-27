package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestEncrypt(t *testing.T) {
	inputFile, _ := os.Open("./test-data/article.txt")
	defer inputFile.Close()

	EncryptFile(inputFile, []byte("GO-OPENSSL-AES-TEST"), 200000, "./test-data/test-encrypt.out")
}

func TestDecrypt(t *testing.T) {

	inputFile, _ := os.Open("./test-data/test-encrypt.out")
	defer inputFile.Close()

	DecryptFile(inputFile, []byte("GO-OPENSSL-AES-TEST"), 200000, "./test-data/article.cipher")

	outputFile, _ := os.Open("./test-data/test-decrypt.out")
	defer outputFile.Close()

	testEncryptedHash := sha256.New()

	// handle hashing io manually
	// buf := make([]byte, 8)
	// for {
	// 	n, err := outputFile.Read(buf)
	// 	if err != nil {
	// 		break
	// 	}
	// 	testEncryptedHash.Write(buf[:n])
	// }

	io.Copy(testEncryptedHash, outputFile)

	// sha256 of article.txt
	const compareHash = "0c74c9a7791623d2f8a743c2283457d23a6e67afcba2381ce1a3a5fd373af01b"
	decryptedHash := hex.EncodeToString(testEncryptedHash.Sum(nil))

	if compareHash != decryptedHash {
		t.Fail()
		fmt.Println(compareHash)
		fmt.Println(decryptedHash)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	inputFile, _ := os.Open("./test-data/article.txt")
	defer inputFile.Close()

	EncryptFile(inputFile, []byte("GO-OPENSSL-AES-TEST"), 200000, "./test-data/test-complete.cipher")

	cipherFile, _ := os.Open("./test-data/test-complete.cipher")
	defer cipherFile.Close()
	DecryptFile(cipherFile, []byte("GO-OPENSSL-AES-TEST"), 200000, "./test-data/test-complete.out")

	outputFile, _ := os.Open("./test-data/test-complete.out")
	defer outputFile.Close()

	testEncryptedHash := sha256.New()
	io.Copy(testEncryptedHash, outputFile)

	// sha256 of article.txt
	const compareHash = "0c74c9a7791623d2f8a743c2283457d23a6e67afcba2381ce1a3a5fd373af01b"
	decryptedHash := hex.EncodeToString(testEncryptedHash.Sum(nil))
	if compareHash != decryptedHash {
		t.Fail()
		fmt.Println(compareHash)
		fmt.Println(decryptedHash)
	}
}

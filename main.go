package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	output            string
	pbkdf2_iter_count string
)

const (
	OPENSSL_MAGIC_STR = "Salted__"
	AES_256_IN_BYTE   = 32 // 256
	BLOCK_IN_BYTE     = 16 // 128
)

// Encrypt/Decrypt AES-256-CBC
func EncryptFile(rawFile *os.File, passphrase []byte, out_filePath string) error {

	// gen salt and pbkdf2
	salt := make([]byte, 8)
	rand.Read(salt)
	pbkdf2_iter, _ := strconv.Atoi(pbkdf2_iter_count)
	key, _ := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2_iter, AES_256_IN_BYTE+BLOCK_IN_BYTE)

	outputFile, _ := os.OpenFile(out_filePath, os.O_CREATE|os.O_RDWR, 0755)
	defer outputFile.Close()
	// write magic string and salt
	outputFile.Write([]byte(OPENSSL_MAGIC_STR))
	outputFile.Write(salt)

	// init AES encryptor
	aesBlock, _ := aes.NewCipher(key[:AES_256_IN_BYTE])
	encrypter := cipher.NewCBCEncrypter(aesBlock, key[AES_256_IN_BYTE:])

	readBuffer := make([]byte, BLOCK_IN_BYTE)
	writeBuffer := make([]byte, BLOCK_IN_BYTE)
	var currentSize int
	var err error
	for {
		currentSize, err = rawFile.Read(readBuffer)
		if err != nil {
			// no more data to read
			return err
		} else {
			if currentSize != BLOCK_IN_BYTE {
				// last block occur, need handle PKCS#7 padding before encrypt
				break
			}
			encrypter.CryptBlocks(writeBuffer, readBuffer)
			outputFile.Write(writeBuffer)
		}
	}

	// write pkcs padding
	if currentSize == 0 {
		readBuffer = bytes.Repeat([]byte{BLOCK_IN_BYTE}, BLOCK_IN_BYTE)
	} else { // currentSize != 0
		padding_len := BLOCK_IN_BYTE - currentSize
		copy(readBuffer[currentSize:], bytes.Repeat([]byte{byte(padding_len)}, padding_len))
	}
	encrypter.CryptBlocks(writeBuffer, readBuffer)
	outputFile.Write(writeBuffer)

	return nil
}

func DecryptFile(encryptfile *os.File, passphrase []byte, out_filePath string) error {

	// get salt from file
	salt := make([]byte, 8)
	encryptfile.Read(salt)

	// gen key by pbkdf2
	pbkdf2_iter, _ := strconv.Atoi(pbkdf2_iter_count)
	key, _ := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2_iter, AES_256_IN_BYTE+BLOCK_IN_BYTE)

	// construct decrypter
	aesBlock, _ := aes.NewCipher(key[:AES_256_IN_BYTE])
	decrypter := cipher.NewCBCDecrypter(aesBlock, key[AES_256_IN_BYTE:])

	outputFile, _ := os.OpenFile(out_filePath, os.O_CREATE|os.O_RDWR, 0755)
	defer outputFile.Close()

	readBuffer := make([]byte, BLOCK_IN_BYTE)
	writeBuffer := make([]byte, BLOCK_IN_BYTE)
	for {
		_, err := encryptfile.Read(readBuffer)
		if err == io.EOF {
			// no more data to read
			break
		} else {
			decrypter.CryptBlocks(writeBuffer, readBuffer)
			outputFile.Write(writeBuffer)
		}
	}

	// remove PKCS#7 padding
	// shift ptr and write again

	// note: In PKCS#7 padding spec
	// a padding content or block will always added
	// no matter last block size are whether or not a full block size (16 bytes)
	padding_len := int(writeBuffer[BLOCK_IN_BYTE-1]) // expect buffer is a AES block size

	if padding_len > BLOCK_IN_BYTE || padding_len < 0 {
		return errors.New("incorrect padding size")
	}

	for i := BLOCK_IN_BYTE - padding_len; i < BLOCK_IN_BYTE; i++ {
		if int(writeBuffer[i]) != padding_len {
			return errors.New("padding content not match")
		}
	}

	remainDataSize := BLOCK_IN_BYTE - padding_len
	filePtr, _ := outputFile.Seek(-BLOCK_IN_BYTE, io.SeekEnd)
	outputFile.Write(writeBuffer[:remainDataSize])
	outputFile.Truncate(filePtr + int64(remainDataSize))

	return nil
}

func CheckOpenFile(filePath string) (*os.File, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		return nil, errors.New("File not exist.")
	}
	file, _ := os.Open(filePath)

	return file, nil
}

func DecryptCommand(cmd *cobra.Command, args []string) {

	file, err := CheckOpenFile(args[0])
	if err != nil {
		fmt.Println("Error: " + err.Error())
	}
	defer file.Close()

	// check if is openssl encrypted AES file - using Salted__ magic string
	file_header := make([]byte, 8)
	file.Read(file_header)

	if OPENSSL_MAGIC_STR != string(file_header) {
		fmt.Println("File is not encrypted by OpenSSL")
		return
	}

	// prompt passphrase
	fmt.Print("Passphrase: ")
	var passphrase, _ = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	result := DecryptFile(file, passphrase, output)
	if result != nil {
		fmt.Println("Decrypt fail: " + result.Error())
	}
}

func EncryptCommand(cmd *cobra.Command, args []string) {

	file, err := CheckOpenFile(args[0])
	if err != nil {
		fmt.Println("Error: " + err.Error())
	}
	defer file.Close()

	fmt.Print("Passphrase: ")
	var passphrase, _ = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	result := EncryptFile(file, passphrase, output)
	if result != nil {
		fmt.Println("Encrypt fail: ", result.Error())
	}
}

var decryptCommand = &cobra.Command{
	Use:   "decrypt <encrypt_filepath>",
	Short: "Decrypt file encrypted by program or OpenSSL AES algorithm",
	Args:  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run:   DecryptCommand,
}

var encryptCommand = &cobra.Command{
	Use:   "encrypt <dncrypt_filepath>",
	Short: "Decrypt file encrypted by program or OpenSSL AES algorithm",
	Args:  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run:   EncryptCommand,
}

// encrypt, in, out, passphrase
// decrypt,
func main() {
	var rootCmd = &cobra.Command{
		Use:   "go-openssl-aes",
		Short: "Encrypt/Decrypt file by openssl aes-256-cbc with pbkdf2 key derivation",
	}

	rootCmd.AddCommand(encryptCommand)
	rootCmd.AddCommand(decryptCommand)
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "./output", "output file path")
	rootCmd.PersistentFlags().StringVarP(&pbkdf2_iter_count, "iter", "i", "200000", "PBKDF2 key derivation iteration")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}
}

package nopcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt file",
	Run: func(cmd *cobra.Command, args []string) {
		input, _ := cmd.Flags().GetString("input")
		key, _ := cmd.Flags().GetString("key")
		output, _ := cmd.Flags().GetString("output")

		// Read input data
		inputFileBytes, err := os.ReadFile(input)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot read input file: %s\n\n", input)
			os.Exit(1)
		}

		data, aes_key, err := encryptAES(inputFileBytes)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: %s\n\n", err)
			os.Exit(1)
		}

		// Read and Validate key
		pemData, err := os.ReadFile(key)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot read key file: %s\n\n", key)
			os.Exit(1)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			fmt.Printf("\n\n[ERROR]: Failed to read PEM data from key\n\n")
			os.Exit(1)
		}

		publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Failed to read PKIX data from key\n\n")
			os.Exit(1)
		}

		publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
		if !ok {
			fmt.Printf("\n\n[ERROR]: Wrong key\n\n")
			os.Exit(1)
		}

		encryptedAESKey, err := encryptRSA(aes_key, publicKey)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Failed to encrypt AES key\n\n")
			os.Exit(1)
		}
		encryptedFileData := joinBytes(data, encryptedAESKey, []byte{0x90, 0x90, 0x90})

		outfile, err := os.Create(output)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Failed to create output file\n\n")
			os.Exit(1)
		}

		defer outfile.Close()
		_, err = outfile.Write(encryptedFileData)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot write to file: %s\n\n", output)
			os.Exit(1)
		}
	},
}

func joinBytes(bytes1 []byte, bytes2 []byte, sep []byte) []byte {
	var joined []byte
	joined = append(joined, bytes1...)
	joined = append(joined, sep...)
	joined = append(joined, bytes2...)
	return joined
}

func encryptRSA(data []byte, key *rsa.PublicKey) ([]byte, error) {
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, key, data)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

func encryptAES(data []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("\nError: %s\n", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("\nError: %s\n", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("\nError: AES initialization vector: %s\n", err)
	}

	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	data = append(data, pad...)

	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)

	encryptedData := append(iv, ciphertext...)

	return encryptedData, key, nil
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().String("input", "", "File to encrypt")
	encryptCmd.PersistentFlags().String("key", "", "Public RSA key")
	encryptCmd.PersistentFlags().String("output", "", "Encrypted file save")

	encryptCmd.MarkPersistentFlagRequired("input")
	encryptCmd.MarkPersistentFlagRequired("key")
	encryptCmd.MarkPersistentFlagRequired("output")
}

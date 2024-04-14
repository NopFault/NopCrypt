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
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt file",
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

		pemData, err := os.ReadFile(key)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot read key file: %s\n\n", key)
			os.Exit(1)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			fmt.Printf("\n\n[ERROR]: Cannot read key PEM data\n\n")
			os.Exit(1)
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot read key PKCS data\n\n")
			os.Exit(1)
		}

		if privateKey.N.Cmp(big.NewInt(0)) == 0 {
			fmt.Printf("\n\n[ERROR]: Wrong key [ Modulus is 0]\n\n")
			os.Exit(1)
		}

		var segments [][]byte = bytes.Split(inputFileBytes, []byte{0x90, 0x90, 0x90})

		aesKey, err := decryptRSA(segments[1], privateKey)
		if err != nil {

			fmt.Printf("\n\n[ERROR]: cannot decrypt AES Key: %s\n\n", err)
			os.Exit(1)
		}

		data, err := decryptAES(segments[0], aesKey)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot decrypt data: %s\n\n", err)
			os.Exit(1)
		}

		outfile, err := os.Create(output)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Failed to create output file\n\n")
			os.Exit(1)
		}

		defer outfile.Close()
		_, err = outfile.Write(data)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot write to file: %s\n\n", output)
			os.Exit(1)
		}
	},
}

func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

func decryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Decrypt ciphertext using RSA private key
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.PersistentFlags().String("input", "", "Encrypted file")
	decryptCmd.PersistentFlags().String("key", "", "Private RSA key")
	decryptCmd.PersistentFlags().String("output", "", "Decrypted file save")

	decryptCmd.MarkPersistentFlagRequired("input")
	decryptCmd.MarkPersistentFlagRequired("key")
	decryptCmd.MarkPersistentFlagRequired("output")
}

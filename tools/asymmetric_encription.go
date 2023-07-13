package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type KeyData struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

func CreateAsymmectricEncription() (*KeyData, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate RSA private key:", err)
		return nil, err
	}

	// Export private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println("Failed to create private key file:", err)
		return nil, err
	}
	pem.Encode(privateKeyFile, privateKeyPEM)
	privateKeyFile.Close()

	fmt.Println("Private key generated and saved to private_key.pem")

	// Extract public key from private key
	publicKey := privateKey.PublicKey

	// Export public key to PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	}
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println("Failed to create public key file:", err)
		return nil, err
	}
	pem.Encode(publicKeyFile, publicKeyPEM)
	publicKeyFile.Close()

	fmt.Println("Public key extracted and saved to public_key.pem")

	publicKeyByte := pem.EncodeToMemory(publicKeyPEM)
	privateKeyByte := pem.EncodeToMemory(privateKeyPEM)
	keydata := KeyData{
		PublicKey:  string(publicKeyByte),
		PrivateKey: string(privateKeyByte),
	}

	test(&privateKey.PublicKey, privateKey)

	return &keydata, err
}

func Encript(value string) (*string, error) {
	publicKeyPEM, err := os.ReadFile("public_key.pem")
	if err != nil {
		return nil, err
	}

	// Parse publickeyPEM into PEM block
	pemBlock, _ := pem.Decode(publicKeyPEM)
	if pemBlock == nil || pemBlock.Type != "RSA PUBLIC KEY" {
		fmt.Println("Failed to decode PEM block")
		return nil, errors.New("failed to decode pem block")
	}

	// Parse PEM block into rsa.PublicKey
	publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return nil, err
	}

	// Encript
	data := []byte(value)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return nil, err
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("Encrypted data (Base64):", ciphertextBase64)
	return &ciphertextBase64, nil
}

func Decrypt(value []byte) (*string, error) {
	privateKeyPEM, err := os.ReadFile("private_key.pem")
	if err != nil {
		return nil, err
	}
	// Decode PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Failed to decode PEM block")
		return nil, errors.New("failed to decode pem block")
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse private key:", err)
		return nil, err
	}

	// Decrypt the ciphertext using private key
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, value)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return nil, err
	}

	// Plaintext (decrypted data)
	fmt.Println("Decrypted data:", string(plaintext))
	res := string(plaintext)

	return &res, nil
}

func test(pubKey *rsa.PublicKey, priKey *rsa.PrivateKey) {
	plainText := "Hello World!"

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(plainText))
	if err != nil {
		panic(err)
	}

	fmt.Println("CipherText: ", ciphertext)

	textAsli, err := rsa.DecryptPKCS1v15(rand.Reader, priKey, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("PlainText: ", string(textAsli))
}

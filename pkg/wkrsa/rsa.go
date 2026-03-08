package wkrsa

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// Deprecated: SignWithMD5 uses MD5 which is cryptographically broken.
// Use SignWithSHA256 instead for new code.
func SignWithMD5(data []byte, pemPrivKey []byte) (string, error) {
	hashMd5 := md5.Sum(data)
	hashed := hashMd5[:]
	block, _ := pem.Decode(pemPrivKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, hashed)
	return base64.StdEncoding.EncodeToString(signature), err
}

// SignWithSHA256 signs data using RSA with SHA-256 hash.
func SignWithSHA256(data []byte, pemPrivKey []byte) (string, error) {
	block, _ := pem.Decode(pemPrivKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

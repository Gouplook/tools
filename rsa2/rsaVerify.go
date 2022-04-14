package rsa2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

const (
	// 私钥 PEMBEGIN 开头
	PEMBEGIN = "-----BEGIN RSA PRIVATE KEY-----\n"
	// 私钥 PEMEND 结尾
	PEMEND = "\n-----END RSA PRIVATE KEY-----"
	// 公钥 PEMBEGIN 开头
	PUBPEMBEGIN = "-----BEGIN PUBLIC KEY-----\n"
	// 公钥 PEMEND 结尾
	PUBPEMEND = "\n-----END PUBLIC KEY-----"
)

//rsa2 签名验签类型
type Rsa2Verify struct {
	PubKey string //公钥字符串
	PrivateKey string //私钥字符串
}

//私钥生成签名
func (r *Rsa2Verify) CreateSign(dataStr string) (sign string, err error)  {
	hash := crypto.SHA256
	shaNew := hash.New()
	shaNew.Write([]byte(dataStr))
	hashed := shaNew.Sum(nil)
	priKey, err := r.ParsePrivateKey(r.PrivateKey)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}


//验证私钥
func (r *Rsa2Verify) ParsePrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	privateKey = r.FormatPrivateKey(privateKey)
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("私钥信息错误！")
	}
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priKey, nil
}

//组装私钥
func (r *Rsa2Verify) FormatPrivateKey(privateKey string) string {
	if !strings.HasPrefix(privateKey, PEMBEGIN) {
		privateKey = PEMBEGIN + privateKey
	}
	if !strings.HasSuffix(privateKey, PEMEND) {
		privateKey = privateKey + PEMEND
	}
	return privateKey
}


//公钥验证签名
func (r *Rsa2Verify) VerifySign(dataStr, sign string) error {
	hash := crypto.SHA256
	hashed := sha256.Sum256([]byte(dataStr))
	pubKey, err := r.ParsePublicKey(r.PubKey)
	if err != nil {
		return err
	}
	sig, _ := base64.StdEncoding.DecodeString(sign)
	err = rsa.VerifyPKCS1v15(pubKey, hash, hashed[:], sig)
	if err != nil {
		return err
	}
	return nil
}

//验证公钥
func (r *Rsa2Verify) ParsePublicKey(publicKey string) (*rsa.PublicKey, error) {
	publicKey = r.FormatPublicKey(publicKey)
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("公钥信息错误！")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*rsa.PublicKey), nil
}

//组装公钥
func (r *Rsa2Verify) FormatPublicKey(publicKey string) string {
	if !strings.HasPrefix(publicKey, PUBPEMBEGIN) {
		publicKey = PUBPEMBEGIN + publicKey
	}
	if !strings.HasSuffix(publicKey, PUBPEMEND) {
		publicKey = publicKey + PUBPEMEND
	}
	return publicKey
}
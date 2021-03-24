package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	enc := flag.String("enc", "", "enc file")
	dec := flag.String("dec", "", "dec file")
	flag.Parse()

	// 运行时只处理一种模式
	if (*enc == "") == (*dec == "") {
		flag.Usage()
		return
	}

	err := encFile(*enc)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = decFile(*dec)
	if err != nil {
		fmt.Println(err)
		return
	}
}

var (
	privateData, publicData []byte
	// 随机生成base64字符编码,稍微增加解码难度
	myBase64 = base64.NewEncoding("Ajk3Zdmw4UVWYg5EIO7MQey9-FGv6_BNflq2CzHT08LSacbnrPptxDJXiuKRh1os").WithPadding(base64.NoPadding)
)

func encFile(path string) (err error) {
	if path == "" {
		return
	}

	publicData, err = os.ReadFile(publicFile)
	if err != nil {
		err = genRsaKey()
		if err != nil {
			return
		}
		publicData, err = os.ReadFile(publicFile)
		if err != nil {
			return
		}
	}

	fr, err := os.Open(path)
	if err != nil {
		return
	}
	defer fr.Close()

	fw, err := os.Create(path + ".dst")
	if err != nil {
		return
	}
	defer fw.Close()

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	encKey, err := rsaEncrypt(key)
	if err != nil {
		return
	}

	_, err = fw.WriteString(encKey + "\x00")
	if err != nil {
		return
	}

	encMode, err := newMyAes(key, aesEnc, fw)
	if err != nil {
		return
	}

	_, err = io.Copy(encMode, fr)
	return
}

func decFile(path string) (err error) {
	if path == "" {
		return
	}

	privateData, err = os.ReadFile(privateFile)
	if err != nil {
		return /* 私钥不存在,需要执行加密流程创建 */
	}

	fr, err := os.Open(path)
	if err != nil {
		return
	}
	defer fr.Close()

	fw, err := os.Create(path + ".src")
	if err != nil {
		return
	}
	defer fw.Close()

	var (
		tmp    = []byte{0}
		encKey = new(strings.Builder)
	)
	for {
		_, err = fr.Read(tmp)
		if err != nil {
			if err != io.EOF {
				break
			}
			return err
		}
		if tmp[0] == 0 {
			break /* 读取第一个为0字符前面的字符串 */
		}
		encKey.WriteByte(tmp[0])
	}

	key, err := rsaDecrypt(encKey.String())
	if err != nil {
		return
	}

	encMode, err := newMyAes(key, aesDec, fw)
	if err != nil {
		return
	}

	_, err = io.Copy(encMode, fr)
	return
}

const (
	privateFile = "private.key"
	publicFile  = "public.key"
	rsaBits     = 1024
)

// 生成rsa公钥和私钥
func genRsaKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	fwPri, err := os.Create(privateFile)
	if err != nil {
		return err
	}
	defer fwPri.Close()

	err = pem.Encode(fwPri, block)
	if err != nil {
		return err
	}

	derPkix, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	fwPub, err := os.Create(publicFile)
	if err != nil {
		return err
	}
	defer fwPub.Close()
	return pem.Encode(fwPub, block)
}

// 加密
func rsaEncrypt(origData []byte) (string, error) {
	block, _ := pem.Decode(publicData)
	if block == nil {
		return "", errors.New("public key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	data, err := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), origData)
	if err != nil {
		return "", err
	}
	return myBase64.EncodeToString(data), nil
}

// 解密
func rsaDecrypt(cipherText string) ([]byte, error) {
	block, _ := pem.Decode(privateData)
	if block == nil {
		return nil, errors.New("private key error")
	}
	prIv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	data, err := myBase64.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, prIv, data)
}

type (
	myAes struct {
		buf    []byte
		w      io.Writer
		stream cipher.Stream
	}
	myAesMode byte
)

const (
	aesEnc myAesMode = iota
	aesDec
)

func newMyAes(key []byte, mode myAesMode, w io.Writer) (io.Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := &myAes{w: w, buf: make([]byte, 32*1024)}
	if mode == aesEnc {
		res.stream = cipher.NewCFBEncrypter(block, key[:block.BlockSize()])
	} else {
		res.stream = cipher.NewCFBDecrypter(block, key[:block.BlockSize()])
	}
	return res, nil
}

func (aes *myAes) Write(p []byte) (int, error) {
	buf := aes.buf // 使用缓存
	if n := len(p); n > len(buf) {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	aes.stream.XORKeyStream(buf, p)
	return aes.w.Write(buf)
}

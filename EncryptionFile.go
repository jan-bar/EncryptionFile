package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	rand2 "math/rand"
	"os"
	"time"
)

func main() {
	enc := flag.String("enc", "", "enc file")
	dec := flag.String("dec", "", "dec file")
	mod := flag.String("mod", "md5", "md5,sha1,sha256,crc32")
	flag.Parse()

	// 运行时只处理一种模式
	if (*enc == "") == (*dec == "") {
		flag.Usage()
		return
	}

	h, ok := map[string]hash.Hash{
		"md5":    md5.New(),
		"sha1":   sha1.New(),
		"sha256": sha256.New(),
		"crc32":  crc32.NewIEEE(),
	}[*mod]
	if !ok {
		h = md5.New()
	}

	err := encFile(*enc, h)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = decFile(*dec, h)
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

func encFile(path string, h hash.Hash) (err error) {
	if path == "" {
		return
	}

	publicData, err = os.ReadFile(publicFile)
	if err != nil {
		err = genRsaKey()
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

	// 预留保存hash值位置,多一个\x00结束符位置
	_, err = fw.Write(make([]byte, 1+myBase64.EncodedLen(h.Size())))
	if err != nil {
		return
	}

	// 将密钥密文存入文件
	_, err = fw.WriteString(encKey + "\x00")
	if err != nil {
		return
	}

	encMode, err := newMyAes(key, aesEnc, h, fw)
	if err != nil {
		return
	}

	_, err = io.Copy(encMode, fr)

	err = fw.Sync() /* 刷新文件 */
	if err != nil {
		return
	}
	_, err = fw.Seek(0, io.SeekStart)
	if err != nil {
		return
	}
	/* 将hash写入头部 */
	_, err = fw.WriteString(myBase64.EncodeToString(encMode.sum()))
	return
}

func decFile(path string, h hash.Hash) (err error) {
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

	br := bufio.NewReader(fr)

	tmpData, err := br.ReadString(0)
	if err != nil {
		return
	}
	sum, err := myBase64.DecodeString(tmpData[:len(tmpData)-1])
	if err != nil {
		return
	}

	tmpData, err = br.ReadString(0)
	if err != nil {
		return
	}
	key, err := rsaDecrypt(tmpData[:len(tmpData)-1])
	if err != nil {
		return
	}

	encMode, err := newMyAes(key, aesDec, h, fw)
	if err != nil {
		return
	}

	_, err = io.Copy(encMode, br)
	if err != nil {
		return
	}
	err = fw.Sync()
	if err != nil {
		return
	}
	// 计算hash结果与文件头的进行比较,不相等表示文件被篡改
	if 0 != bytes.Compare(sum, encMode.sum()) {
		return errors.New("file hash not match")
	}
	return nil
}

type (
	myAes struct {
		buf    []byte
		w      io.Writer
		h      hash.Hash
		mode   myAesMode
		stream cipher.Stream
	}
	myAesMode byte
)

const (
	aesEnc myAesMode = iota
	aesDec
)

func newMyAes(key []byte, mode myAesMode, h hash.Hash, w io.Writer) (*myAes, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := &myAes{w: w, h: h, mode: mode, buf: make([]byte, 32*1024)}
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
	if aes.mode == aesEnc {
		aes.h.Write(p) /* 加密前源文件计算hash */
	} else {
		aes.h.Write(buf) /* 解密后源文件计算hash */
	}
	return aes.w.Write(buf)
}

func (aes *myAes) sum() []byte {
	return aes.h.Sum(nil)
}

/* rsa相关 */
const (
	privateFile = "private.key"
	publicFile  = "public.key"
)

// 生成rsa公钥和私钥
func genRsaKey() error {
	rand2.Seed(time.Now().UnixNano())

	// 经测试,要加密32字节数据最少需要337bits
	// 因此按照如下随机一个长度,使rsa公私钥长度也随机
	bits := rand2.Intn(200) + 337
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
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
	data := new(bytes.Buffer)
	err = pem.Encode(data, block)
	if err != nil {
		return err
	}
	publicData = data.Bytes() // 保存公钥数据
	return os.WriteFile(publicFile, publicData, 0666)
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

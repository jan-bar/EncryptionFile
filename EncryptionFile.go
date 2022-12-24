package EncryptionFile

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"io"
)

const bufLen = 32 * 1024 // 同io.Copy里面的默认长度

// EncData
//  @Description: 加密数据
//  @param r      数据来源读出流
//  @param w      加密数据写入流
//  @param pubKey 公钥数据
//  @param h      指定hash校验方法
//  @return error 返回错误
func EncData(r io.Reader, w io.Writer, pubKey []byte, h hash.Hash) error {
	tmp := make([]byte, bufLen)

	const aesKeyIvLen = aes.BlockSize + 32
	_, err := rand.Read(tmp[:aesKeyIvLen])
	if err != nil {
		return err
	}

	encKey, err := RsaEncrypt(pubKey, tmp[:aesKeyIvLen])
	if err != nil {
		return err
	}

	n := len(encKey) // 将rsa密文长度和rsa密文写入头部
	head := append(tmp[aesKeyIvLen:aesKeyIvLen], byte(n), byte(n>>8))
	head = append(head, encKey...)
	_, err = w.Write(head)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(tmp[:32])
	if err != nil {
		return err
	}
	aw := &aesEncDec{hash: h, w: w,
		stream: cipher.NewCFBEncrypter(block, tmp[32:aesKeyIvLen]),
	}

	// 将内容使用aes进行加密并写入
	_, err = copyBuffer(aw, r, tmp)
	if err != nil {
		return err
	}

	// hash值为加密后数据的hash,这样可以保证每次hash值都会变化
	// 上一版是加密前数据的hash,这样可以穷举aes的key+iv计算和hash匹配就能完成破解
	// 所以使用加密后数据计算hash是最合理的方式
	_, err = w.Write(aw.sum()) // 最后写入内容hash值
	return err
}

// DecData
//  @Description:  解密数据
//  @param r       密文数据读入流
//  @param w       解密后数据写入流
//  @param priKey  私钥数据
//  @param h       指定hash校验方法
//  @return error  返回错误
func DecData(r io.Reader, w io.Writer, priKey []byte, h hash.Hash) error {
	var (
		br  = bufio.NewReader(r)
		tmp = make([]byte, bufLen)
	)
	_, err := io.ReadFull(br, tmp[:2])
	if err != nil {
		return err
	}

	n := int(tmp[0]) | int(tmp[1])<<8
	if n > bufLen {
		// 正常数据基本不会出错,这里防止异常数据时返回错误
		return errors.New("len(rsa) out of index")
	}
	// 根据rsa长度读取rsa密文
	_, err = io.ReadFull(br, tmp[:n])
	if err != nil {
		return err
	}

	key, err := RsaDecrypt(priKey, tmp[:n])
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}
	ar := &aesEncDec{hash: h, r: br, hSize: h.Size(),
		stream: cipher.NewCFBDecrypter(block, key[32:]),
	}

	// 使用aes解密,并写入w
	_, err = copyBuffer(w, ar, tmp)
	if err != nil {
		return err
	}

	if ar.sumDiff() {
		return errors.New("file hash not match")
	}
	return nil
}

// -----------------------------------------------------------------------------

type aesEncDec struct {
	r *bufio.Reader
	w io.Writer

	hash  hash.Hash
	hSize int
	hCrc  []byte

	stream cipher.Stream
}

func (aes *aesEncDec) Write(p []byte) (n int, err error) {
	aes.stream.XORKeyStream(p, p)
	n, err = aes.w.Write(p)
	if err == nil {
		aes.hash.Write(p[:n]) // 加密后的数据计算hash
	}
	return
}

func (aes *aesEncDec) Read(p []byte) (n int, err error) {
	n, err = aes.r.Read(p)
	if err == nil {
		aes.hCrc, err = aes.r.Peek(aes.hSize)
		if err != nil {
			// Peek只有读n个字节才会返回成功,只有少于n个字节才会报错
			// 因此上次Peek成功,则说明缓存一定有n个字节可读
			// 因为 (len(p)=32*1024) > aes.hSize ,本次Read一定包含上次Peek内容
			// 本次Peek失败,说明读取到io.EOF结束标记,本次读取就完成了所有读取
			// 此时(p + aes.hCrc)共同组成包含crc内容的最后一次处理数据
			// len(aes.hCrc) == aes.hSize时err==nil,会多走一次循环,下次才会到这里
			// 因此err!=nil时必定存在关系: 0 <= len(aes.hCrc) < aes.hSize
			// 下面就组装crc内容,并设置n使之继续解密crc之前的数据
			// 本注释用于说明io.Reader接口读取时一定可以得到最后aes.hSize数据
			// 如果异常数据,则aes.hCrc一定不正常,sumDiff会确保长度和内容正确
			lc := n - aes.hSize + len(aes.hCrc)
			aes.hCrc = append(p[lc:n], aes.hCrc...)
			n = lc
		}
		if n > 0 {
			aes.hash.Write(p[:n]) // 解密前的数据计算hash
			aes.stream.XORKeyStream(p, p[:n])
		}
	}
	return
}

// 加密时返回计算源文件的hash值
func (aes *aesEncDec) sum() []byte { return aes.hash.Sum(nil) }

// 解密时判断计算的hash和读出的hash是否不同
func (aes *aesEncDec) sumDiff() bool {
	crc := aes.hash.Sum(nil)
	if len(crc) == len(aes.hCrc) {
		for i, v := range crc {
			if aes.hCrc[i] != v {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------

// GenRsaKey
//  @Description: 生成rsa公私钥对
//  @param bits   生成位数
//  @param pub    公钥写入流
//  @param pri    私钥写入流
//  @return error 返回错误
func GenRsaKey(bits int, pub, pri io.Writer) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(pri, block)
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
	return pem.Encode(pub, block)
}

// RsaEncrypt
//  @Description:   rsa加密逻辑
//  @param pubKey    公钥数据
//  @param origData  待加密数据
//  @return []byte   返回加密后数据
//  @return error    返回错误
func RsaEncrypt(pubKey, origData []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), origData)
}

// RsaDecrypt
//  @Description:     rsa解密逻辑
//  @param priKey     私钥数据
//  @param cipherText 密文
//  @return []byte    解密后数据
//  @return error     返回错误
func RsaDecrypt(priKey, cipherText []byte) ([]byte, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	prIv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, prIv, cipherText)
}

// copy io.copyBuffer ,去掉不需要的判断和类型断言
func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	var (
		nr, nw int
		er, ew error
	)
	for {
		nr, er = src.Read(buf)
		if nr > 0 {
			nw, ew = dst.Write(buf[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

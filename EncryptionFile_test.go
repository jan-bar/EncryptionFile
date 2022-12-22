package EncryptionFile

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"log"
	"testing"
)

func TestEnc(t *testing.T) {
	const bufLen2 = 2 * bufLen

	var (
		tmpBuf0 = bytes.NewBuffer(make([]byte, 0, bufLen2))
		tmpBuf1 = bytes.NewBuffer(make([]byte, 0, bufLen2))
	)
	err := GenRsaKey(2048, tmpBuf0, tmpBuf1)
	if err != nil {
		log.Fatal(err)
	}

	var (
		tmp    = make([]byte, bufLen2)
		h      = md5.New()
		priKey = make([]byte, tmpBuf1.Len())
		pubKey = make([]byte, tmpBuf0.Len())
	)
	// 生成一对用于测试的公私钥
	copy(priKey, tmpBuf1.Bytes())
	copy(pubKey, tmpBuf0.Bytes())
	for i := 0; i < bufLen2; i++ {
		// 循环测试任意长度的数据加解密,该长度覆盖 *bufio.Reader 默认 4096 长度
		// 也要覆盖 bufLen 的长度,因此这里取 2 * bufLen ,充分测试各种长度数据
		// 测试数据使用随机值,多次测试通过才确保该算法没有问题
		_, err = rand.Read(tmp[:i])
		if err != nil {
			t.Fatal(err)
		}
		tmpBuf0.Reset()
		tmpBuf0.Write(tmp[:i])

		tmpBuf1.Reset()
		h.Reset()
		err = EncData(tmpBuf0, tmpBuf1, pubKey, h)
		if err != nil {
			t.Fatal(err)
		}

		tmpBuf0.Reset()
		h.Reset() // 解密实际上也会校验hash是否一致
		err = DecData(tmpBuf1, tmpBuf0, priKey, h)
		if err != nil {
			t.Fatal(err)
		}

		// 判断原始内容和解密后内容是否一致
		if !bytes.Equal(tmp[:i], tmpBuf0.Bytes()) {
			t.Fatal("dec(data) != tmp[:i]")
		}
	}
}

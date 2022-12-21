package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"

	"github.com/jan-bar/EncryptionFile"
)

func main() {
	org := flag.String("f", "", "enc file path")
	flag.Parse()

	src := *org // dst为生成的加密文件,cmp是通过解密dst生成的文件
	dst, cmp := src+".dst", src+".cmp"

	var pri, pub bytes.Buffer // 生成一对公私钥数据
	err := EncryptionFile.GenRsaKey(2048, &pub, &pri)
	if err != nil {
		log.Fatal(err)
	}

	//goland:noinspection GoUnhandledErrorResult
	enc := func() error {
		fr, err := os.Open(src)
		if err != nil {
			return err
		}
		defer fr.Close()

		fw, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer fw.Close()

		return EncryptionFile.EncData(fr, fw, pub.Bytes(), md5.New())
	}

	if err = enc(); err != nil {
		log.Fatal(err)
	}

	//goland:noinspection GoUnhandledErrorResult
	dec := func() error {
		fr, err := os.Open(dst)
		if err != nil {
			return err
		}
		defer fr.Close()

		fw, err := os.Create(cmp)
		if err != nil {
			return err
		}
		defer fw.Close()

		return EncryptionFile.DecData(fr, fw, pri.Bytes(), md5.New())
	}

	if err = dec(); err != nil {
		log.Fatal(err)
	}

	md5Src, err := md5file(src)
	if err != nil {
		log.Fatal(err)
	}

	md5Org, err := md5file(cmp)
	if err != nil {
		log.Fatal(err)
	}

	if md5Src != md5Org {
		log.Fatalf("src(%s) != org(%s)", md5Src, md5Org)
	}
}

func md5file(s string) (string, error) {
	fr, err := os.Open(s)
	if err != nil {
		return "", err
	}
	//goland:noinspection GoUnhandledErrorResult
	defer fr.Close()

	h := md5.New()
	_, err = io.Copy(h, fr)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

package EncryptionFile

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	rand2 "math/rand"
	"os"
	"testing"
	"time"
)

// go test -v -run TestEnc
func TestEnc(t *testing.T) {
	rand2.Seed(time.Now().Unix())

	const bufLen2 = 2 * bufLen

	var (
		tmpBuf0 = bytes.NewBuffer(make([]byte, 0, bufLen2))
		tmpBuf1 = bytes.NewBuffer(make([]byte, 0, bufLen2))
	)

	err := GenRsaKey(0, tmpBuf0, tmpBuf1)
	if err != nil {
		log.Fatal(err)
	}

	var (
		tmp    = make([]byte, bufLen2)
		h      = md5.New()
		priKey = make([]byte, tmpBuf1.Len())
		pubKey = make([]byte, tmpBuf0.Len())
		lr     = new(limitReader)

		cfbEncStream = GenEncCipher(cipher.NewCFBEncrypter)
		cfbDecStream = GenDecCipher(cipher.NewCFBDecrypter)
	)

	copy(priKey, tmpBuf1.Bytes()) // save the private key
	copy(pubKey, tmpBuf0.Bytes()) // save the public key

	// go test -v -run "TestEnc/EncryptAndDecryptFile"
	//goland:noinspection GoUnhandledErrorResult
	t.Run("EncryptAndDecryptFile", func(t *testing.T) {
		encFile := func(f string) error {
			fr, err := os.Open(f)
			if err != nil {
				return err
			}
			defer fr.Close()

			fw, err := os.Create(f + ".enc")
			if err != nil {
				return err
			}
			defer fw.Close()

			h.Reset()
			return EncData(fr, fw, pubKey, h, cfbEncStream)
		}

		decFile := func(f string) error {
			fr, err := os.Open(f + ".enc")
			if err != nil {
				return err
			}
			defer fr.Close()

			fw, err := os.Create(f + ".dec")
			if err != nil {
				return err
			}
			defer fw.Close()

			h.Reset()
			return DecData(fr, fw, priKey, h, cfbDecStream)
		}

		const fName = "EncryptionFile.go"
		err = encFile(fName)
		if err != nil {
			t.Fatal("encryption error", err)
		}

		err = decFile(fName)
		if err != nil {
			t.Fatal("decrypt error", err)
		}

		fOrg, err := os.ReadFile(fName)
		if err != nil {
			t.Fatal(err)
		}
		fDec, err := os.ReadFile(fName + ".dec")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fOrg, fDec) {
			t.Fatal("original file and decrypted file are different")
		}
	})

	test := func(limit int, enc, dec func(r io.Reader, w io.Writer, h hash.Hash) error) error {
		_, err = rand.Read(tmp[:limit]) // Generate random encrypted data
		if err != nil {
			return err
		}

		tmpBuf0.Reset()
		tmpBuf0.Write(tmp[:limit])
		tmpBuf1.Reset()
		h.Reset()

		if err = enc(tmpBuf0, tmpBuf1, h); err != nil {
			return err
		}

		tmpBuf0.Reset()
		h.Reset()
		lr.n = rand2.Intn(limit) + 1 // random read block size
		lr.r = tmpBuf1

		if err = dec(lr, tmpBuf0, h); err != nil {
			return err
		}

		if !bytes.Equal(tmp[:limit], tmpBuf0.Bytes()) {
			return errors.New("dec(data) != tmp[:i]")
		}

		tmpBuf0.Reset()
		tmpBuf0.Write(tmp[:limit])
		h.Reset()
		tmpBuf1.Reset()

		lr.r = tmpBuf0
		if err = dec(lr, tmpBuf1, h); err == nil {
			return errors.New("decrypt error data successfully")
		}

		return nil
	}

	// go test -v -run "TestEnc/TestCipher"
	t.Run("TestCipher", func(t *testing.T) {
		testCipher := []struct {
			enc  EncCipher
			dec  DecCipher
			name string
		}{
			{name: "cfb", enc: cfbEncStream, dec: cfbDecStream},
			{name: "ctr", enc: GenEncCipher(cipher.NewCTR), dec: GenDecCipher(cipher.NewCTR)},
			{name: "ofb", enc: GenEncCipher(cipher.NewOFB), dec: GenDecCipher(cipher.NewOFB)},
			{name: "cbc", enc: GenEncCipher(cipher.NewCBCEncrypter), dec: GenDecCipher(cipher.NewCBCDecrypter)},
			{name: "gcm", enc: GenEncCipher(cipher.NewGCM), dec: GenDecCipher(cipher.NewGCM)},
		}

		cnt := make(chan int, 1)
		go func() {
			for {
				fmt.Print("  ", <-cnt, "\r")
				time.Sleep(time.Second)
			}
		}()

		// test different length data,fully validated algorithm
		for i := 1; i < bufLen2; i++ {
			for _, cp := range testCipher {
				err = test(i, func(r io.Reader, w io.Writer, h hash.Hash) error {
					return EncData(r, w, pubKey, h, cp.enc)
				}, func(r io.Reader, w io.Writer, h hash.Hash) error {
					return DecData(r, w, priKey, h, cp.dec)
				})
				if err != nil {
					t.Fatal(cp.name, err)
				}
			}

			select {
			case cnt <- i * 100 / bufLen2:
			default:
			}
		}
	})
}

type limitReader struct {
	r io.Reader
	n int
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n < len(p) {
		return l.r.Read(p[:l.n])
	}

	return l.r.Read(p)
}

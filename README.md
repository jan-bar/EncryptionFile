## EncryptionFile

[中文文档](README_CN.md)

for specific usage, please read: [EncryptionFile_test.go](EncryptionFile_test.go)

### implementation

the password is related to the corresponding algorithm

I have this format here: `password = [key + 0 + iv/nonce]`

| rsa ciphertext length | rsa encrypted password data | algorithm encrypted content | hash value                                                        |
|-----------------------|-----------------------------|-----------------------------|-------------------------------------------------------------------|
| len(rsa(password))    | rsa(password)               | algorithm(content)          | hash.Sum(len(rsa(password)) + rsa(password) + algorithm(content)) |

### cipher.AEAD

password composition: `password = [key + 0 + nonce]`

the nonce needs to be taken out correctly, and it must be ensured that there is no 0 in the key

### cipher.Stream

password composition: `password = [key + 0 + iv]`

### cipher.BlockMode

password composition: `password = [key + 0 + iv]`

### example

support encryption schemes in golang standard library: `cipher.AEAD,cipher.Stream,cipher.BlockMode`

at the same time, several encryption schemes of aes are built in: `CFB,CTR,OFB,CBC,GCM`

```go
// an encryption scheme can be specified with the built-in method
// GenEncCipher(cipher.NewCFBEncrypter)
// GenEncCipher(cipher.NewCTR)
// GenEncCipher(cipher.NewOFB)
// GenEncCipher(cipher.NewCBCEncrypter)
// GenEncCipher(cipher.NewGCM)
EncData(Reader, Writer, pubKey, md5.New(), GenEncCipher(cipher.NewCFBEncrypter))

// an decryption scheme can be specified with the built-in method
// GenDecCipher(cipher.NewCFBDecrypter)
// GenDecCipher(cipher.NewCTR)
// GenDecCipher(cipher.NewOFB)
// GenDecCipher(cipher.NewCBCDecrypter)
// GenDecCipher(cipher.NewGCM)
DecData(Reader, Writer, priKey, md5.New(), GenDecCipher(cipher.NewCFBDecrypter))
```

you can also refer to [GenEncCipher](EncryptionFile.go#GenEncCipher) to write the method of generating encryption

you can also refer to [GenDecCipher](EncryptionFile.go#GenDecCipher) to write the method of generating decryption

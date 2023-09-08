## EncryptionFile

[english document](README.md)

具体使用请阅读: [EncryptionFile_test.go](EncryptionFile_test.go)

### implementation

密码与对应的算法有关

密码的格式: `password = [key + 0 + iv/nonce]`

| rsa密文长度            | rsa加密密码数据     | 具体算法加密内容           | 校验值                                                               |
|--------------------|---------------|--------------------|-------------------------------------------------------------------|
| len(rsa(password)) | rsa(password) | algorithm(content) | hash.Sum(len(rsa(password)) + rsa(password) + algorithm(content)) |

### cipher.AEAD

密码组成: `password = [key + 0 + nonce]`

需要正确解析nonce，因此必须保证key中不存在0

### cipher.Stream

密码组成: `password = [key + 0 + iv]`

### cipher.BlockMode

密码组成: `password = [key + 0 + iv]`

### example

支持golang标准库中的加密方案: `cipher.AEAD,cipher.Stream,cipher.BlockMode`

同时内置了AES多种加密方案: `CFB,CTR,OFB,CBC,GCM`

```go
// 可以使用内置方法指定加密方案
// GenEncCipher(cipher.NewCFBEncrypter)
// GenEncCipher(cipher.NewCTR)
// GenEncCipher(cipher.NewOFB)
// GenEncCipher(cipher.NewCBCEncrypter)
// GenEncCipher(cipher.NewGCM)
EncData(Reader, Writer, pubKey, md5.New(), GenEncCipher(cipher.NewCFBEncrypter))

// 可以使用内置方法指定解密方案
// GenDecCipher(cipher.NewCFBDecrypter)
// GenDecCipher(cipher.NewCTR)
// GenDecCipher(cipher.NewOFB)
// GenDecCipher(cipher.NewCBCDecrypter)
// GenDecCipher(cipher.NewGCM)
DecData(Reader, Writer, priKey, md5.New(), GenDecCipher(cipher.NewCFBDecrypter))
```

也可以参考 [GenEncCipher](EncryptionFile.go#GenEncCipher) 编写生成加密的方法

也可以参考 [GenDecCipher](EncryptionFile.go#GenDecCipher) 编写生成解密的方法

## EncryptionFile
> 加密解密文件  
> 由于需要使用流式加解密因此选用AES CFB模式  
> 使用RSA将随机密钥加密,并将密文存入文件头部  
> 加密文件只需要提供可执行程序和公钥  
> 解密文件只需要提供可执行程序和私钥  
> 即使同一个文件每次加密结果都不一样,安全系数极高  

## 使用方法
加密：`go run EncryptionFile.go -enc EncryptionFile.go`  
会产生`EncryptionFile.go.dst`的加密文件  

解密：`go run EncryptionFile.go -dec EncryptionFile.go.dst`  
会产生`EncryptionFile.go.dst.src`的解密文件  

执行：`diff EncryptionFile.go.dst.src EncryptionFile.go`  
可以发现解密文件没有问题。

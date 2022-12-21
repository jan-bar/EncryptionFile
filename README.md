## EncryptionFile

> 加密解密文件  
> 由于需要使用流式加解密因此选用AES CFB模式  
> 使用RSA将随机密钥加密,并将密文存入文件头部  
> 加密文件只需要提供可执行程序和公钥  
> 解密文件只需要提供可执行程序和私钥  
> 即使同一个文件每次加密结果都不一样,安全系数极高  
> 可以指定计算hash方法,最终会在末尾存入hash值  

如下为加密后文件内容,为了让加解密都使用io.Reader和io.Writer,将hash放在末尾

这样不需要io.Seeker这类更新偏移,或者传入数据长度。一切都只认io.Reader返回io.EOF时结束

| rsa密文长度            | rsa加密aes密码后的密文 | aes加密内容      | 数据hash值    |
|--------------------|----------------|--------------|------------|
| len(rsa(password)) | rsa(password)  | aesEnc(data) | hash(data) |

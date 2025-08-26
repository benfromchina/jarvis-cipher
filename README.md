# Jarvis Cipher

`jarvis-cipher` 是一个基于 Java 的加密工具库，提供多种加密算法实现，包括对称加密、非对称加密、签名与验证等功能。该项目支持 RSA 和 SM（国密）算法，适用于需要高安全性与合规性的应用场景。

## 模块结构

该项目由多个模块组成：

- **jarvis-cipher-core**：核心接口与抽象类定义，包括 AEAD 加密、隐私加密、签名与验证等通用接口和工具类。
- **jarvis-cipher-rsa**：RSA 算法的具体实现，包括密钥处理、证书管理、加密、解密、签名与验证。
- **jarvis-cipher-sm**：国密算法（SM2、SM4）的具体实现，包括密钥处理、证书管理、加密、解密、签名与验证。

## 功能特性

- **AEAD 加密**：支持 AES 和 SM4 的 AEAD 模式加密与解密。
- **非对称加密**：支持 RSA 和 SM2 的加密与解密。
- **签名与验证**：支持 RSA 和 SM2 的签名与验证功能。
- **PEM 工具**：支持从 PEM 文件加载密钥与证书，以及将密钥与证书转换为 PEM 格式。
- **证书管理**：支持创建根证书与签发客户端证书。

## 使用示例

### AEAD 加密（AES）

```java
byte[] key = ...; // 密钥
AeadCipher aeadCipher = new AeadAesCipher(key);
String ciphertext = aeadCipher.encrypt(associatedData, nonce, plaintext);
String decrypted = aeadCipher.decrypt(associatedData, nonce, ciphertext);
```

### 非对称加密（RSA）

```java
PublicKey publicKey = RSAPemUtils.loadPublicKeyFromPath("public_key.pem");
PrivateKey privateKey = RSAPemUtils.loadPrivateKeyFromPath("private_key.pem");

PrivacyEncryptor encryptor = new RSAPrivacyEncryptor(publicKey);
PrivacyDecryptor decryptor = new RSAPrivacyDecryptor(privateKey);

String ciphertext = encryptor.encrypt("plaintext");
String decrypted = decryptor.decrypt(ciphertext);
```

### 签名与验证（SM2）

```java
PrivateKey privateKey = SMPemUtils.loadPrivateKeyFromPath("sm2_private_key.pem");
PublicKey publicKey = SMPemUtils.loadPublicKeyFromPath("sm2_public_key.pem");

Signer signer = new SM2Signer(privateKey);
Verifier verifier = new SM2Verifier(publicKey);

String signature = signer.sign("message");
boolean isValid = verifier.verify("message", signature);
```

## 测试资源

测试模块包含完整的测试用例，验证加密、解密、签名、验证等功能的正确性。测试资源目录中包含用于测试的证书与密钥文件。

## 许可证

本项目基于 [Apache-2.0](LICENSE) 协议发布。
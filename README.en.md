[![](https://img.shields.io/badge/Maven%20Central-v1.0.0-brightgreen)](https://central.sonatype.com/artifact/io.github.benfromchina/jarvis-cipher/1.0.0)
[![](https://img.shields.io/badge/Release-v1.0.0-blue)](https://gitee.com/jarvis-lib/jarvis-cipher/releases/v2.0.3)
[![](https://img.shields.io/badge/License-Apache--2.0-9cf)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![](https://img.shields.io/badge/JDK-8+-9cf)]()

# Jarvis Cipher

`jarvis-cipher` is a Java-based cryptographic tool library that provides implementations of various encryption algorithms, including symmetric encryption, asymmetric encryption, signature, and verification. This project supports RSA and SM (Chinese National Standard) algorithms, making it suitable for applications requiring high security and compliance.

## Installation

### For RSA

```xml
<dependency>
    <groupId>io.github.benfromchina</groupId>
    <artifactId>jarvis-cipher-rsa</artifactId>
    <version>1.0.0</version>
</dependency>
```

### For SM (Chinese National Standard)

```xml
<dependency>
    <groupId>io.github.benfromchina</groupId>
    <artifactId>jarvis-cipher-sm</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Module Structure

The project consists of multiple modules:

- **jarvis-cipher-core**: Core interface and abstract class definitions, including general interfaces and utility classes for AEAD encryption, privacy encryption, signature, and verification.
- **jarvis-cipher-rsa**: Concrete implementation of the RSA algorithm, including key handling, certificate management, encryption, decryption, signature, and verification.
- **jarvis-cipher-sm**: Concrete implementation of the Chinese National Standard algorithms (SM2, SM4), including key handling, certificate management, encryption, decryption, signature, and verification.

## Key Features

- **AEAD Encryption**: Supports AEAD mode encryption and decryption for AES and SM4.
- **Asymmetric Encryption**: Supports encryption and decryption using RSA and SM2.
- **Signature & Verification**: Supports signature and verification using RSA and SM2.
- **PEM Utilities**: Supports loading keys and certificates from PEM files, as well as converting keys and certificates to PEM format.
- **Certificate Management**: Supports creating root certificates and issuing client certificates.

## Usage Examples

### AEAD Encryption (AES)

```java
byte[] key = ...; // Secret key
AeadCipher aeadCipher = new AeadAesCipher(key);
String ciphertext = aeadCipher.encrypt(associatedData, nonce, plaintext);
String decrypted = aeadCipher.decrypt(associatedData, nonce, ciphertext);
```

### Asymmetric Encryption (RSA)

```java
PublicKey publicKey = RSAPemUtils.loadPublicKeyFromPath("public_key.pem");
PrivateKey privateKey = RSAPemUtils.loadPrivateKeyFromPath("private_key.pem");

PrivacyEncryptor encryptor = new RSAPrivacyEncryptor(publicKey);
PrivacyDecryptor decryptor = new RSAPrivacyDecryptor(privateKey);

String ciphertext = encryptor.encrypt("plaintext");
String decrypted = decryptor.decrypt(ciphertext);
```

### Signature & Verification (SM2)

```java
PrivateKey privateKey = SMPemUtils.loadPrivateKeyFromPath("sm2_private_key.pem");
PublicKey publicKey = SMPemUtils.loadPublicKeyFromPath("sm2_public_key.pem");

Signer signer = new SM2Signer(privateKey);
Verifier verifier = new SM2Verifier(publicKey);

String signature = signer.sign("message");
boolean isValid = verifier.verify("message", signature);
```

## Test Resources

The test module contains comprehensive test cases to validate the correctness of encryption, decryption, signature, and verification functionalities. The test resource directory includes certificate and key files used for testing.

## License

This project is released under the [Apache-2.0](LICENSE) license.
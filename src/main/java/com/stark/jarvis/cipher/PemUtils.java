package com.stark.jarvis.cipher;

import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import static java.util.Objects.requireNonNull;

/**
 * PEM 工具类
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class PemUtils {

    /**
     * 生成 RSA CA 根证书
     *
     * @param keyPair      RSA 公私钥秘钥对
     * @param subjectInfo  证书主题信息
     * @param serialNumber 证书序列号
     * @param years        有效期年，10 到 20 之间，默认 10
     * @return RSA CA 根证书
     */
    public static X509Certificate createRootCert(KeyPair keyPair,
                                                 SubjectInfo subjectInfo,
                                                 BigInteger serialNumber,
                                                 Integer years) throws IOException, GeneralSecurityException {
        requireNonNull(keyPair);
        requireNonNull(subjectInfo);
        requireNonNull(serialNumber);
        if (years != null) {
            if (years < 10 || years > 20) {
                throw new IllegalArgumentException("有效期必须在 10 年到 20 年之间");
            }
        } else {
            years = 10;
        }

        // 1. 证书有效期
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000 * years);

        // 2. 证书主题信息（自签名 CA subject=issuer）
        X500Name issuer = new X500Name(subjectInfo.toX500Name());

        // 3. 构造 X509 v3 证书信息
        String algorithm = "SHA256withRSA";
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(startDate, endDate));
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        certInfo.set(X509CertInfo.SUBJECT, issuer);
        certInfo.set(X509CertInfo.ISSUER, issuer);
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(algorithm)));

        // 4. 设置为 CA：basicConstraints=CA:true
        CertificateExtensions exts = new CertificateExtensions();
        exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(true, -1));
        KeyUsageExtension kue = new KeyUsageExtension();
        kue.set(KeyUsageExtension.KEY_CERTSIGN, true);
        kue.set(KeyUsageExtension.CRL_SIGN, true);
        exts.set(KeyUsageExtension.NAME, kue);
        certInfo.set(X509CertInfo.EXTENSIONS, exts);

        // 5. 用私钥签名生成证书
        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(keyPair.getPrivate(), algorithm);
        return cert;
    }

    /**
     * 颁发 RSA 客户端证书
     *
     * @param caCert          RSA CA 证书
     * @param caPrivateKey    RSA CA 私钥
     * @param clientPublicKey RSA 客户端公私
     * @param subjectInfo     证书主题信息
     * @param serialNumber    证书序列号
     * @param years           有效期年，1 到 3 之间，默认 1
     * @return RSA 客户端证书
     */
    public static X509Certificate issueClientCert(X509Certificate caCert,
                                                  PrivateKey caPrivateKey,
                                                  PublicKey clientPublicKey,
                                                  SubjectInfo subjectInfo,
                                                  BigInteger serialNumber,
                                                  Integer years) throws Exception {

        requireNonNull(caCert);
        requireNonNull(caPrivateKey);
        requireNonNull(clientPublicKey);
        requireNonNull(subjectInfo);
        requireNonNull(serialNumber);
        if (years != null) {
            if (years < 1 || years > 3) {
                throw new IllegalArgumentException("有效期必须在 1 年到 3 年之间");
            }
        } else {
            years = 1;
        }

        // 1. 证书有效期
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000 * years); // 10年

        // 2. 获取签发者
        X500Name issuer = new X500Name(caCert.getIssuerX500Principal().getName());

        // 3. 证书主题信息（自签名 CA subject=issuer）
        X500Name subject = new X500Name(subjectInfo.toX500Name());

        // 4. 构造 X509 v3 证书信息
        String algorithm = "SHA256withRSA";
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(startDate, endDate));
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        certInfo.set(X509CertInfo.SUBJECT, subject);
        certInfo.set(X509CertInfo.ISSUER, issuer);
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(clientPublicKey));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(algorithm)));

        // 5. 添加基本约束(非CA证书)
        CertificateExtensions exts = new CertificateExtensions();
        exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, -1));
        KeyUsageExtension kue = new KeyUsageExtension();
        kue.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
        kue.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
        kue.set(KeyUsageExtension.DATA_ENCIPHERMENT, true);
        exts.set(KeyUsageExtension.NAME, kue);
        certInfo.set(X509CertInfo.EXTENSIONS, exts);

        // 6. 用CA证书私钥签名生成证书
        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(caPrivateKey, algorithm);
        return cert;
    }

    /**
     * 验证客户端证书是否由 CA 签发
     * <p>校验不通过时抛出异常
     *
     * @param clientCert 客户端证书
     * @param caCert     CA 证书
     */
    public static void verifyCert(X509Certificate clientCert, X509Certificate caCert) {
        // 1. 验证签名
        try {
            clientCert.verify(caCert.getPublicKey());
        } catch (Exception e) {
            throw new RuntimeException("证书不是由CA签发", e);
        }

        // 2. 验证有效期
        try {
            clientCert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("证书已过期", e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("证书不合法", e);
        }

        // 3. 验证基本约束(不应是CA证书)
        if (clientCert.getBasicConstraints() != -1) {
            throw new RuntimeException("客户端证书不能是CA证书");
        }

        // 4. 验证密钥用法(可选)
        boolean[] keyUsage = clientCert.getKeyUsage();
        if (keyUsage != null) {
            if (!keyUsage[0]) {
                throw new RuntimeException("证书未被授权用于数字签名");
            }
            if (!keyUsage[2]) {
                throw new RuntimeException("证书未被授权用于密钥加密");
            }
            if (!keyUsage[3]) {
                throw new RuntimeException("证书未被授权用于数据加密");
            }
        }
    }

    /**
     * 生成 RSA 密钥对
     *
     * @return RSA 密钥对
     */
    public static KeyPair createKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * 私钥转 pem 字符串
     *
     * @param privateKey RSA 私钥
     * @return pem 字符串
     */
    public static String privateKeyToPEM(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\n" +
                bytesToPEM(privateKey.getEncoded()) + "\n" +
                "-----END PRIVATE KEY-----\n";
    }

    /**
     * 公钥转 pem 字符串
     *
     * @param publicKey RSA 公钥
     * @return pem 字符串
     */
    public static String publicKeyToPEM(PublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\n" +
                bytesToPEM(publicKey.getEncoded()) + "\n" +
                "-----END PUBLIC KEY-----\n";
    }

    /**
     * X509 证书转 pem 字符串
     *
     * @param cert X509 证书
     * @return pem 字符串
     */
    public static String certToPEM(X509Certificate cert) throws CertificateEncodingException {
        return "-----BEGIN CERTIFICATE-----\n" +
                bytesToPEM(cert.getEncoded()) + "\n" +
                "-----END CERTIFICATE-----\n";
    }

    /**
     * 从 RSA 私钥字符串中加载 RSA 私钥
     *
     * @param privateKeyString RSA 私钥字符串
     * @return RSA 私钥
     */
    public static PrivateKey loadPrivateKeyFromString(String privateKeyString) {
        privateKeyString = privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        return loadPrivateKey(Base64.getDecoder().decode(privateKeyString));
    }

    /**
     * 读取 RSA 私钥文件获取 RSA 私钥
     *
     * @param privateKeyPath RSA 私钥路径
     * @return RSA 私钥
     */
    public static PrivateKey loadPrivateKeyFromPath(String privateKeyPath) {
        return loadPrivateKeyFromString(IOUtils.loadStringFromPath(privateKeyPath));
    }

    /**
     * 加载私钥
     *
     * @param encoded 私钥字节数组
     * @return 私钥
     */
    public static PrivateKey loadPrivateKey(byte[] encoded) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 从公钥字符串中加载公钥
     *
     * @param publicKeyString 公钥字符串
     * @return 公钥
     */
    public static PublicKey loadPublicKeyFromString(String publicKeyString) {
        publicKeyString = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        return loadPublicKey(Base64.getDecoder().decode(publicKeyString));
    }

    /**
     * 读取 RSA 公钥文件获取 RSA 公钥
     *
     * @param publicKeyPath RSA 公钥路径
     * @return RSA 公钥
     */
    public static PublicKey loadPublicKeyFromPath(String publicKeyPath) {
        return loadPublicKeyFromString(IOUtils.loadStringFromPath(publicKeyPath));
    }

    /**
     * 加载公钥
     *
     * @param encoded 公钥字节数组
     * @return 公钥
     */
    public static PublicKey loadPublicKey(byte[] encoded) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 读取 RSA 证书输入流获取 RSA X509 证书
     *
     * @param in RSA 证书输入流
     * @return RSA X509 证书
     */
    public static X509Certificate loadX509FromStream(InputStream in) {
        try (BufferedInputStream bis = new BufferedInputStream(in)) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
                cert.checkValidity();
                return cert;
            } catch (CertificateExpiredException e) {
                throw new RuntimeException("证书已过期", e);
            } catch (CertificateNotYetValidException e) {
                throw new RuntimeException("证书尚未生效", e);
            } catch (CertificateException e) {
                throw new RuntimeException("无效的证书文件", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("读取证书文件失败", e);
        }
    }

    /**
     * 读取 RSA 证书文件获取 RSA X509 证书
     *
     * @param certPath RSA 证书文件路径
     * @return RSA X509 证书
     */
    public static X509Certificate loadX509FromPath(String certPath) {
        try (FileInputStream in = new FileInputStream(certPath)) {
            return loadX509FromStream(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * 从 RSA 证书字符串中加载 RSA X509 证书
     *
     * @param certString RSA 证书字符串
     * @return X509 证书
     */
    public static X509Certificate loadX509FromString(String certString) {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8))) {
            return loadX509FromStream(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * 获取 16 进制证书序列号
     *
     * @param cert X509 证书
     * @return 16 进制证书序列号
     */
    public static String getSerialNumber(X509Certificate cert) {
        return cert.getSerialNumber().toString(Constant.HEX).toUpperCase();
    }

    /**
     * 转换为 PEM 格式字符串
     *
     * @param bytes 字节数组
     * @return PEM 格式字符串
     */
    public static String bytesToPEM(byte[] bytes) {
        return Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(bytes);
    }

}

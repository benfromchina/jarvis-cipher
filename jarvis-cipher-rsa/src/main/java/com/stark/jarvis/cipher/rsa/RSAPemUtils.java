package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.IOUtils;
import com.stark.jarvis.cipher.core.PemUtils;
import com.stark.jarvis.cipher.core.SubjectInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

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
public class RSAPemUtils extends PemUtils {

    private static final String ALGORITHM = "RSA";

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final int KEY_SIZE = 2048;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成 RSA 密钥对
     *
     * @return RSA 密钥对
     */
    public static KeyPair createKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("不支持的算法", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("加密服务提供者不存在", e);
        }
    }

    /**
     * 生成 RSA CA 根证书
     *
     * @param keyPair      RSA 公私钥秘钥对
     * @param serialNumber 证书序列号
     * @param subjectInfo  证书主题信息
     * @param years        有效期年，10 到 20 之间，默认 10
     * @return RSA CA 根证书
     */
    public static X509Certificate createRootCert(KeyPair keyPair,
                                                 BigInteger serialNumber,
                                                 SubjectInfo subjectInfo,
                                                 Integer years) throws IOException, GeneralSecurityException, OperatorCreationException {
        requireNonNull(keyPair);
        requireNonNull(serialNumber);
        requireNonNull(subjectInfo);
        if (years != null) {
            if (years < 10 || years > 20) {
                throw new IllegalArgumentException("有效期必须在 10 年到 20 年之间");
            }
        } else {
            years = 10;
        }

        // 1. 构建 CA 根证书
        X500Name issuer = new X500Name(subjectInfo.toX500Name());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000 * years);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                issuer,
                keyPair.getPublic()
        );

        // 2. 设置扩展：CA=true
        certBuilder
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // 3. 用私钥签名生成证书
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder);
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
                                                  BigInteger serialNumber,
                                                  SubjectInfo subjectInfo,
                                                  Integer years) throws Exception {

        requireNonNull(caCert);
        requireNonNull(caPrivateKey);
        requireNonNull(clientPublicKey);
        requireNonNull(serialNumber);
        requireNonNull(subjectInfo);
        if (years != null) {
            if (years < 1 || years > 3) {
                throw new IllegalArgumentException("有效期必须在 1 年到 3 年之间");
            }
        } else {
            years = 1;
        }

        // 1. 构建 CA 根证书
        X500Name issuer = new X500Name(caCert.getIssuerX500Principal().getName());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000 * years);
        X500Name subject = new X500Name(subjectInfo.toX500Name());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                clientPublicKey
        );

        // 2. 设置扩展：CA=true
        certBuilder
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

        // 3. 用私钥签名生成证书
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder);
    }

    /**
     * 获取 KeyFactory 实例
     *
     * @return KeyFactory 实例
     */
    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("不支持的算法", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("加密服务提供者不存在", e);
        }
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
            KeyFactory keyFactory = getKeyFactory();
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("不合法的私钥", e);
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
            KeyFactory keyFactory = getKeyFactory();
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("不合法的公钥", e);
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
                CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
                cert.checkValidity();
                return cert;
            } catch (CertificateExpiredException e) {
                throw new RuntimeException("证书已过期", e);
            } catch (CertificateNotYetValidException e) {
                throw new RuntimeException("证书尚未生效", e);
            } catch (CertificateException e) {
                throw new RuntimeException("无效的证书文件", e);
            } catch (NoSuchProviderException e) {
                throw new RuntimeException("加密服务提供者不存在", e);
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
            throw new UncheckedIOException("读取证书文件失败", e);
        }
    }

    /**
     * 从 RSA 证书字符串中加载 RSA X509 证书
     *
     * @param certString RSA 证书字符串
     * @return X509 证书
     */
    public static X509Certificate loadX509FromString(String certString) {
        try (ByteArrayInputStream in = new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8))) {
            return loadX509FromStream(in);
        } catch (IOException e) {
            throw new UncheckedIOException("读取证书字符串失败", e);
        }
    }

}

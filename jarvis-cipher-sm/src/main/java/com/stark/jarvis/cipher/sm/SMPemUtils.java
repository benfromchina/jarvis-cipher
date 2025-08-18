package com.stark.jarvis.cipher.sm;

import com.stark.jarvis.cipher.core.IOUtils;
import com.stark.jarvis.cipher.core.PemUtils;
import com.stark.jarvis.cipher.core.SubjectInfo;
import com.tencent.kona.KonaProvider;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.sun.security.x509.*;

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
 * 国密 PEM 工具
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class SMPemUtils extends PemUtils {

    private static final String ALGORITHM = "EC";

    private static final String SIGNATURE_ALGORITHM = "SM3withSM2";

    static {
        Security.addProvider(new KonaProvider());
    }

    /**
     * 生成国密公私钥密钥对
     *
     * @return 国密公私钥密钥对
     */
    public static KeyPair createKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, KonaProvider.NAME);
            keyPairGenerator.initialize(SM2ParameterSpec.instance());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new UnsupportedOperationException("不支持的算法", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("加密服务提供者不存在", e);
        }
    }

    /**
     * 生成国密CA根证书
     *
     * @param keyPair      国密公私钥秘钥对
     * @param serialNumber 证书序列号
     * @param subjectInfo  证书主题信息
     * @param years        有效期年，10到20之间，默认10
     * @return 国密CA根证书
     */
    public static X509Certificate createRootCert(KeyPair keyPair,
                                                 BigInteger serialNumber,
                                                 SubjectInfo subjectInfo,
                                                 Integer years) throws IOException, GeneralSecurityException {
        requireNonNull(keyPair);
        requireNonNull(subjectInfo);
        requireNonNull(serialNumber);
        if (years != null) {
            if (years < 10 || years > 20) {
                throw new IllegalArgumentException("有效期必须在10年到20年之间");
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
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.setValidity(new CertificateValidity(startDate, endDate));
        certInfo.setSerialNumber(new CertificateSerialNumber(serialNumber));
        certInfo.setSubject(issuer);
        certInfo.setIssuer(issuer);
        certInfo.setKey(new CertificateX509Key(keyPair.getPublic()));
        certInfo.setVersion(new CertificateVersion(CertificateVersion.V3));
        certInfo.setAlgorithmId(new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));

        // 4. 设置为 CA：basicConstraints=CA:true
        CertificateExtensions exts = new CertificateExtensions();
        exts.setExtension(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(true, -1));
        KeyUsageExtension kue = new KeyUsageExtension();
        kue.set(KeyUsageExtension.KEY_CERTSIGN, true);
        kue.set(KeyUsageExtension.CRL_SIGN, true);
        exts.setExtension(KeyUsageExtension.NAME, kue);
        certInfo.setExtensions(exts);

        // 5. 用私钥签名生成证书
        return X509CertImpl.newSigned(certInfo, keyPair.getPrivate(), SIGNATURE_ALGORITHM);
    }

    /**
     * 颁发国密客户端证书
     *
     * @param caCert          国密CA证书
     * @param caPrivateKey    国密CA私钥
     * @param clientPublicKey 国密客户端公私
     * @param serialNumber    证书序列号
     * @param subjectInfo     证书主题信息
     * @param years           有效期年，1到3之间，默认1
     * @return 国密客户端证书
     */
    public static X509Certificate issueClientCert(X509Certificate caCert,
                                                  PrivateKey caPrivateKey,
                                                  PublicKey clientPublicKey,
                                                  BigInteger serialNumber,
                                                  SubjectInfo subjectInfo,
                                                  Integer years) throws IOException, GeneralSecurityException {
        requireNonNull(caCert);
        requireNonNull(caPrivateKey);
        requireNonNull(clientPublicKey);
        requireNonNull(subjectInfo);
        requireNonNull(serialNumber);
        if (years != null) {
            if (years < 1 || years > 3) {
                throw new IllegalArgumentException("有效期必须在1年到3年之间");
            }
        } else {
            years = 1;
        }

        // 1. 证书有效期
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000 * years);

        // 2. 获取签发者
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());

        // 3. 证书主题信息（自签名 CA subject=issuer）
        X500Name subject = new X500Name(subjectInfo.toX500Name());

        // 4. 构造 X509 v3 证书信息
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.setValidity(new CertificateValidity(startDate, endDate));
        certInfo.setSerialNumber(new CertificateSerialNumber(serialNumber));
        certInfo.setSubject(subject);
        certInfo.setIssuer(issuer);
        certInfo.setKey(new CertificateX509Key(clientPublicKey));
        certInfo.setVersion(new CertificateVersion(CertificateVersion.V3));
        certInfo.setAlgorithmId(new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));

        // 5. 添加基本约束(非CA证书)
        CertificateExtensions exts = new CertificateExtensions();
        exts.setExtension(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, -1));
        KeyUsageExtension kue = new KeyUsageExtension();
        kue.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
        kue.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
        kue.set(KeyUsageExtension.DATA_ENCIPHERMENT, true);
        kue.set(KeyUsageExtension.KEY_AGREEMENT, true);
        exts.setExtension(KeyUsageExtension.NAME, kue);
        certInfo.setExtensions(exts);

        // 6. 用CA证书私钥签名生成证书
        return X509CertImpl.newSigned(certInfo, caPrivateKey, SIGNATURE_ALGORITHM);
    }

    /**
     * 获取 KeyFactory 实例
     *
     * @return KeyFactory 实例
     */
    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(ALGORITHM, KonaProvider.NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("不支持的算法", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("加密服务提供者不存在", e);
        }
    }

    /**
     * 从国密私钥字符串中加载国密私钥
     *
     * @param privateKeyString 国密私钥字符串
     * @return 国密私钥
     */
    public static PrivateKey loadPrivateKeyFromString(String privateKeyString) {
        privateKeyString = privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        return loadPrivateKey(Base64.getDecoder().decode(privateKeyString));
    }

    /**
     * 读取国密私钥文件获取国密私钥
     *
     * @param privateKeyPath 国密私钥文件路径
     * @return 国密私钥
     */
    public static PrivateKey loadPrivateKeyFromPath(String privateKeyPath) {
        return loadPrivateKeyFromString(IOUtils.loadStringFromPath(privateKeyPath));
    }

    /**
     * 加载国密私钥
     *
     * @param encoded 国密私钥字节数组
     * @return 国密私钥
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
     * 从国密公钥字符串中加载国密公钥
     *
     * @param publicKeyString 国密公钥字符串
     * @return 国密公钥
     */
    public static PublicKey loadPublicKeyFromString(String publicKeyString) {
        publicKeyString = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        return loadPublicKey(Base64.getDecoder().decode(publicKeyString));
    }

    /**
     * 读取国密公钥文件获取国密公钥
     *
     * @param publicKeyPath 国密公钥文件路径
     * @return 国密公钥
     */
    public static PublicKey loadPublicKeyFromPath(String publicKeyPath) {
        return loadPublicKeyFromString(IOUtils.loadStringFromPath(publicKeyPath));
    }

    /**
     * 加载国密公钥
     *
     * @param encoded 国密公钥字节数组
     * @return 国密公钥
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
     * 读取国密X509证书输入流获取国密X509证书
     *
     * @param in 国密X509证书输入流
     * @return 国密X509证书
     */
    public static X509Certificate loadX509FromStream(InputStream in) {
        try (BufferedInputStream bis = new BufferedInputStream(in)) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", KonaProvider.NAME);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
                cert.checkValidity();
                return cert;
            } catch (CertificateExpiredException e) {
                throw new RuntimeException("证书已过期", e);
            } catch (CertificateNotYetValidException e) {
                throw new RuntimeException("证书尚未生效", e);
            } catch (CertificateException | NoSuchProviderException e) {
                throw new RuntimeException("无效的证书文件", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("读取证书文件失败", e);
        }
    }

    /**
     * 读取国密X509证书文件加载国密X509证书
     *
     * @param certPath 国密X509证书路径
     * @return 国密X509证书
     */
    public static X509Certificate loadX509FromPath(String certPath) {
        try (FileInputStream in = new FileInputStream(certPath)) {
            return loadX509FromStream(in);
        } catch (IOException e) {
            throw new UncheckedIOException("读取证书文件失败", e);
        }
    }

    /**
     * 从国密X509证书字符串加载国密X509证书
     *
     * @param certString 国密X509证书字符串
     * @return 国密X509证书
     */
    public static X509Certificate loadX509FromString(String certString) {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8))) {
            return loadX509FromStream(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException("读取证书字符串失败", e);
        }
    }

}

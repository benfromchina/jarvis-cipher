package com.stark.jarvis.cipher.core;

import lombok.SneakyThrows;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * PEM 工具类
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class PemUtils {

    /**
     * 验证客户端证书是否由CA签发
     * <p>校验不通过时抛出异常
     *
     * @param clientCert 客户端证书
     * @param caCert     CA证书
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
     * 私钥转 pem 字符串
     *
     * @param privateKey 私钥
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
     * @param publicKey 公钥
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
    @SneakyThrows
    public static String certToPEM(X509Certificate cert) {
        return "-----BEGIN CERTIFICATE-----\n" +
                bytesToPEM(cert.getEncoded()) + "\n" +
                "-----END CERTIFICATE-----\n";
    }

    /**
     * 获取16进制证书序列号
     *
     * @param cert X509证书
     * @return 16进制证书序列号
     */
    public static String getSerialNumber(X509Certificate cert) {
        return cert.getSerialNumber().toString(16).toUpperCase();
    }

    /**
     * 字节数组转换为PEM格式字符串
     *
     * @param bytes 字节数组
     * @return PEM格式字符串
     */
    public static String bytesToPEM(byte[] bytes) {
        return Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(bytes);
    }

}

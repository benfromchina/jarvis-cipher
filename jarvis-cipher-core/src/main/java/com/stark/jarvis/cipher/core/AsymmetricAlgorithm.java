package com.stark.jarvis.cipher.core;

import lombok.Getter;

/**
 * 枚举非对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @version 1.0.0
 * @since 2025/8/21
 */
@Getter
public enum AsymmetricAlgorithm {

    RSA("SHA256-RSA2048", "BC", "RSA", "SHA256withRSA", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),

    SM2("SM2-WITH-SM3", "Kona", "EC", "SM2", "SM2");

    /**
     * 算法名称
     */
    private final String name;

    /**
     * 提供者名称
     */
    private final String provider;

    /**
     * 密钥算法名称
     */
    private final String keyAlgorithm;

    /**
     * 签名算法名称
     */
    private final String signatureAlgorithm;

    /**
     * 加密使用的模式（算法名称/工作模式/填充方案）
     */
    private final String transformation;

    AsymmetricAlgorithm(String name, String provider, String keyAlgorithm, String signatureAlgorithm, String transformation) {
        this.name = name;
        this.provider = provider;
        this.keyAlgorithm = keyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.transformation = transformation;
    }

}

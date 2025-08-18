package com.stark.jarvis.cipher.signer;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * 抽象的签名器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public abstract class AbstractSigner implements Signer {

    /**
     * 自定义的签名算法名称
     */
    private final String algorithm;

    /**
     * 签名算法标准名称
     */
    private final String algorithmName;

    /**
     * 私钥
     */
    private final PrivateKey privateKey;

    /**
     * 构造签名器
     *
     * @param algorithm     自定义的签名算法名称
     * @param algorithmName 获取Signature对象时指定的算法，例如SHA256withRSA
     * @param privateKey    私钥
     */
    protected AbstractSigner(String algorithm, String algorithmName, PrivateKey privateKey) {
        this.algorithm = requireNonNull(algorithm);
        this.algorithmName = requireNonNull(algorithmName);
        this.privateKey = requireNonNull(privateKey);
    }

    @Override
    public String sign(String message) {
        requireNonNull(message);

        byte[] sign;
        try {
            Signature signature = Signature.getInstance(algorithmName);
            signature.initSign(privateKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            sign = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("当前签名算法不支持 " + algorithmName, e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(algorithm + " 签名使用了一个不合法的私钥", e);
        } catch (SignatureException e) {
            throw new RuntimeException("签名过程中发生错误", e);
        }
        return Base64.getEncoder().encodeToString(sign);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

}

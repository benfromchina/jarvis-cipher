package com.stark.jarvis.cipher.core.signer;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;

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
     * 非对称加密算法
     */
    private final AsymmetricAlgorithm algorithm;

    /**
     * 私钥
     */
    private final PrivateKey privateKey;

    /**
     * 构造签名器
     *
     * @param algorithm  非对称加密算法
     * @param privateKey 私钥
     */
    protected AbstractSigner(AsymmetricAlgorithm algorithm, PrivateKey privateKey) {
        this.algorithm = requireNonNull(algorithm);
        this.privateKey = requireNonNull(privateKey);
    }

    @Override
    public String sign(String message) {
        requireNonNull(message);

        byte[] sign;
        try {
            Signature signature = Signature.getInstance(algorithm.getSignatureAlgorithm());
            signature.initSign(privateKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            sign = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("当前签名算法不支持 " + algorithm.getSignatureAlgorithm(), e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(algorithm + " 签名使用了一个不合法的私钥", e);
        } catch (SignatureException e) {
            throw new RuntimeException("签名过程中发生错误", e);
        }
        return Base64.getEncoder().encodeToString(sign);
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getName();
    }

}

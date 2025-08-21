package com.stark.jarvis.cipher.core.verifier;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * 抽象的验签器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public abstract class AbstractVerifier implements Verifier {

    /**
     * 非对称加密算法
     */
    AsymmetricAlgorithm algorithm;

    /**
     * 公钥
     */
    protected final PublicKey publicKey;

    /**
     * 构造验签器
     *
     * @param algorithm 非对称加密算法
     * @param publicKey 公钥
     */
    protected AbstractVerifier(AsymmetricAlgorithm algorithm, PublicKey publicKey) {
        this.algorithm = requireNonNull(algorithm);
        this.publicKey = publicKey;
    }

    public boolean verify(String message, String signature) {
        try {
            Signature sign = Signature.getInstance(algorithm.getSignatureAlgorithm());
            sign.initVerify(publicKey);
            sign.update(message.getBytes(StandardCharsets.UTF_8));
            return sign.verify(Base64.getDecoder().decode(signature));
        } catch (SignatureException e) {
            return false;
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("验证使用了一个不合法的证书", e);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("当前 Java 环境不支持 " + algorithm.getSignatureAlgorithm(), e);
        }
    }

}

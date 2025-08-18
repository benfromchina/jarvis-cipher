package com.stark.jarvis.cipher.verifier;

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
     * 签名算法标准名称
     */
    protected final String algorithmName;

    /**
     * 公钥
     */
    protected final PublicKey publicKey;

    /**
     * 构造验签器
     *
     * @param algorithmName 获取Signature对象时指定的算法，例如SHA256withRSA
     * @param publicKey     公钥
     */
    protected AbstractVerifier(String algorithmName, PublicKey publicKey) {
        this.algorithmName = requireNonNull(algorithmName);
        this.publicKey = publicKey;
    }

    public boolean verify(String message, String signature) {
        try {
            Signature sign = Signature.getInstance(algorithmName);
            sign.initVerify(publicKey);
            sign.update(message.getBytes(StandardCharsets.UTF_8));
            return sign.verify(Base64.getDecoder().decode(signature));
        } catch (SignatureException e) {
            return false;
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("验证使用了一个不合法的证书", e);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("当前 Java 环境不支持 " + algorithmName, e);
        }
    }

}

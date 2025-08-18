package com.stark.jarvis.cipher.privacy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * 抽象的敏感数据加密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public abstract class AbstractPrivacyEncryptor implements PrivacyEncryptor {

    /**
     * 公钥
     */
    private final PublicKey publicKey;

    /**
     * 密码算法
     */
    private final Cipher cipher;

    /**
     * 构造敏感信息加密的抽象类
     *
     * @param transformation 加密使用的模式（算法名称/工作模式/填充方案）
     * @param publicKey      加密使用的公钥
     */
    protected AbstractPrivacyEncryptor(String transformation, PublicKey publicKey) {
        this.publicKey = requireNonNull(publicKey);
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException(
                    "当前 Java 环境不支持 " + transformation, e);
        }
    }

    @Override
    public String encrypt(String plaintext) {
        requireNonNull(plaintext);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("RSA加密使用了一个不合法的公钥", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException("明文长度过长", e);
        }
    }

}

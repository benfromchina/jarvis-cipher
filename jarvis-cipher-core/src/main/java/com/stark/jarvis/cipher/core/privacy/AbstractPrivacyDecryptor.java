package com.stark.jarvis.cipher.core.privacy;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * 抽象的敏感信息解密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public abstract class AbstractPrivacyDecryptor implements PrivacyDecryptor {

    /**
     * 私钥
     */
    private final PrivateKey privateKey;

    /**
     * 密码算法
     */
    private final Cipher cipher;

    /**
     * 构造敏感信息解密的抽象类
     *
     * @param algorithm  非对称加密算法
     * @param privateKey 加密使用的私钥
     */
    protected AbstractPrivacyDecryptor(AsymmetricAlgorithm algorithm, PrivateKey privateKey) {
        this.privateKey = requireNonNull(privateKey);
        try {
            cipher = Cipher.getInstance(algorithm.getTransformation());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("当前 Java 环境不支持 " + algorithm.getTransformation(), e);
        }
    }

    @Override
    public String decrypt(String ciphertext) {
        requireNonNull(ciphertext);
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)), StandardCharsets.UTF_8);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("给定的私钥无法用来解密", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("解密失败", e);
        }
    }

}

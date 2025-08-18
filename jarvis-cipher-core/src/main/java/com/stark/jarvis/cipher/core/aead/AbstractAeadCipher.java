package com.stark.jarvis.cipher.core.aead;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 抽象的对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public abstract class AbstractAeadCipher implements AeadCipher {

    /**
     * 算法名称
     */
    private final String algorithm;

    /**
     * 加密使用的模式（算法名称/工作模式/填充方案）
     */
    private final String transformation;

    /**
     * 认证标签字节数
     */
    private final int tagLengthBit;

    /**
     * 秘钥
     */
    private final byte[] key;

    /**
     * 构造对称加密算法
     *
     * @param algorithm      算法名称
     * @param transformation 加密使用的模式（算法名称/工作模式/填充方案）
     * @param tagLengthBit   认证标签字节数
     * @param key            秘钥
     */
    protected AbstractAeadCipher(String algorithm, String transformation, int tagLengthBit, byte[] key) {
        this.algorithm = algorithm;
        this.transformation = transformation;
        this.tagLengthBit = tagLengthBit;
        this.key = key;
    }

    /**
     * 加密并转换为字符串
     *
     * @param associatedData AAD，额外的认证加密数据，可以为空
     * @param nonce          IV，随机字符串初始化向量
     * @param plaintext      明文
     * @return Base64编码的密文
     */
    public String encrypt(byte[] associatedData, byte[] nonce, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm), new GCMParameterSpec(tagLengthBit, nonce));
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
        } catch (InvalidKeyException
                 | InvalidAlgorithmParameterException
                 | BadPaddingException
                 | IllegalBlockSizeException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 解密并转换为字符串
     *
     * @param associatedData AAD，额外的认证加密数据，可以为空
     * @param nonce          IV，随机字符串初始化向量
     * @param ciphertext     密文
     * @return UTF-8编码的明文
     */
    public String decrypt(byte[] associatedData, byte[] nonce, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm), new GCMParameterSpec(tagLengthBit, nonce));
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (InvalidKeyException
                 | InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException
                 | NoSuchPaddingException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("解密失败", e);
        }
    }

}

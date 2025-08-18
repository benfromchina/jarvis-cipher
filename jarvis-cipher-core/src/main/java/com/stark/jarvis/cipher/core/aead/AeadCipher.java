package com.stark.jarvis.cipher.core.aead;

/**
 * 对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public interface AeadCipher {

    /**
     * 加密并转换为字符串
     *
     * @param associatedData AAD，额外的认证加密数据，可以为空
     * @param nonce          IV，随机字符串初始化向量
     * @param plaintext      明文
     * @return Base64编码的密文
     */
    String encrypt(byte[] associatedData, byte[] nonce, byte[] plaintext);

    /**
     * 解密并转换为字符串
     *
     * @param associatedData AAD，额外的认证加密数据，可以为空
     * @param nonce          IV，随机字符串初始化向量
     * @param ciphertext     密文
     * @return UTF-8编码的明文
     */
    String decrypt(byte[] associatedData, byte[] nonce, byte[] ciphertext);

}

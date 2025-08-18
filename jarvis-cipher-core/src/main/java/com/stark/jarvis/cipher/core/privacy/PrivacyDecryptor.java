package com.stark.jarvis.cipher.core.privacy;

/**
 * 敏感信息解密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public interface PrivacyDecryptor {

    /**
     * 解密并转换为字符串
     *
     * @param ciphertext 密文
     * @return UTF-8编码的明文
     */
    String decrypt(String ciphertext);

}

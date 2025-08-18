package com.stark.jarvis.cipher.privacy;

/**
 * 敏感信息加密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public interface PrivacyEncryptor {

    /**
     * 加密并转换为字符串
     *
     * @param plaintext 明文
     * @return Base64编码的密文
     */
    String encrypt(String plaintext);

}

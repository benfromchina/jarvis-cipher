package com.stark.jarvis.cipher.core.verifier;

/**
 * 验签器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public interface Verifier {

    /**
     * 验证签名
     *
     * @param message   签名信息
     * @param signature 签名
     * @return 是否验证通过
     */
    boolean verify(String message, String signature);

}

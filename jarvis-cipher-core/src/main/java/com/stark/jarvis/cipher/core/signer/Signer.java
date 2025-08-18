package com.stark.jarvis.cipher.core.signer;

/**
 * 签名器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public interface Signer {

    /**
     * 生成签名
     *
     * @param message 签名信息
     * @return 签名
     */
    String sign(String message);

    /**
     * 获取自定义的签名算法名称
     *
     * @return 自定义的签名算法名称
     */
    String getAlgorithm();

}

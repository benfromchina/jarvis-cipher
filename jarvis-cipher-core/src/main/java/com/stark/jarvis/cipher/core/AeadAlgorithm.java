package com.stark.jarvis.cipher.core;

import lombok.Getter;

/**
 * 枚举对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @version 1.0.0
 * @since 2025/8/21
 */
@Getter
public enum AeadAlgorithm {

    AES("AES/GCM/NoPadding"),

    SM4("SM4/GCM/NoPadding");

    /**
     * 加密使用的模式（算法名称/工作模式/填充方案）
     */
    private final String transformation;

    AeadAlgorithm(String transformation) {
        this.transformation = transformation;
    }

}

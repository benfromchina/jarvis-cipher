package com.stark.jarvis.cipher.rsa.aead;

import com.stark.jarvis.cipher.core.AeadAlgorithm;
import com.stark.jarvis.cipher.core.aead.AbstractAeadCipher;

/**
 * AES对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class AeadAesCipher extends AbstractAeadCipher {

    private static final int TAG_LENGTH_BIT = 128;

    public AeadAesCipher(byte[] key) {
        super(AeadAlgorithm.AES, TAG_LENGTH_BIT, key);
    }

}

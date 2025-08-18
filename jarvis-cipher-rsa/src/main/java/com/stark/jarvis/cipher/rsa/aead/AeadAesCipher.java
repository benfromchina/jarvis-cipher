package com.stark.jarvis.cipher.rsa.aead;

import com.stark.jarvis.cipher.core.aead.AbstractAeadCipher;

/**
 * AES对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class AeadAesCipher extends AbstractAeadCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128;

    private static final String ALGORITHM = "AES";

    public AeadAesCipher(byte[] key) {
        super(ALGORITHM, TRANSFORMATION, TAG_LENGTH_BIT, key);
    }

}

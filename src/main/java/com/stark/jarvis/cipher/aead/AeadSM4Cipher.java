package com.stark.jarvis.cipher.aead;

import com.stark.jarvis.cipher.Constant;
import com.tencent.kona.KonaProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

/**
 * 国密SM4对称加密算法
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class AeadSM4Cipher extends AbstractAeadCipher {

    static {
        Security.addProvider(new KonaProvider());
    }

    private static final String TRANSFORMATION = "SM4/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128;

    private static final String ALGORITHM = "SM4";

    /**
     * @param key 密钥
     */
    public AeadSM4Cipher(byte[] key) {
        super(ALGORITHM, TRANSFORMATION, TAG_LENGTH_BIT, covertSM4Key(key));
    }

    /**
     * 取SM3摘要的前128位，将key转化成SM4使用的密钥
     *
     * @param key 秘钥
     * @return SM4Gcm的密钥
     */
    private static byte[] covertSM4Key(byte[] key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", KonaProvider.NAME);
            return Arrays.copyOf(md.digest(key), Constant.HEX);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

}

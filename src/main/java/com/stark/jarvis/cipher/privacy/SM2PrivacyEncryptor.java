package com.stark.jarvis.cipher.privacy;

import com.tencent.kona.KonaProvider;

import java.security.PublicKey;
import java.security.Security;

/**
 * 国密SM2敏感信息加密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class SM2PrivacyEncryptor extends AbstractPrivacyEncryptor {

    static {
        Security.addProvider(new KonaProvider());
    }

    public SM2PrivacyEncryptor(PublicKey publicKey) {
        super("SM2", publicKey);
    }

}

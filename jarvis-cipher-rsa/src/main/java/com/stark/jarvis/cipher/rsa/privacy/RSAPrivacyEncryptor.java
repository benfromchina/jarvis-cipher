package com.stark.jarvis.cipher.rsa.privacy;

import com.stark.jarvis.cipher.core.privacy.AbstractPrivacyEncryptor;

import java.security.PublicKey;

/**
 * RSA敏感信息加密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class RSAPrivacyEncryptor extends AbstractPrivacyEncryptor {

    public RSAPrivacyEncryptor(PublicKey publicKey) {
        super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", publicKey);
    }

}

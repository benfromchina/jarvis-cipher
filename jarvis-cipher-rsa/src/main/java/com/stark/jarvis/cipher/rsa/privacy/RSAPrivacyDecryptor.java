package com.stark.jarvis.cipher.rsa.privacy;

import com.stark.jarvis.cipher.core.privacy.AbstractPrivacyDecryptor;

import java.security.PrivateKey;

/**
 * RSA敏感信息解密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class RSAPrivacyDecryptor extends AbstractPrivacyDecryptor {

    public RSAPrivacyDecryptor(PrivateKey privateKey) {
        super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", privateKey);
    }

}

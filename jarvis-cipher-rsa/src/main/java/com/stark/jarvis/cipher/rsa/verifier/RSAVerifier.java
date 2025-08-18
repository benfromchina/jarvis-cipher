package com.stark.jarvis.cipher.rsa.verifier;

import com.stark.jarvis.cipher.core.verifier.AbstractVerifier;

import java.security.PublicKey;

/**
 * RSA验签器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class RSAVerifier extends AbstractVerifier {

    public RSAVerifier(PublicKey publicKey) {
        super("SHA256withRSA", publicKey);
    }

}

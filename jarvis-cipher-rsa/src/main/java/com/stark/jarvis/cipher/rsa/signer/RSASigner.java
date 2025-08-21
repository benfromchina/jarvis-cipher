package com.stark.jarvis.cipher.rsa.signer;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;
import com.stark.jarvis.cipher.core.signer.AbstractSigner;

import java.security.PrivateKey;

/**
 * RSA签名器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class RSASigner extends AbstractSigner {

    public RSASigner(PrivateKey privateKey) {
        super(AsymmetricAlgorithm.RSA, privateKey);
    }

}

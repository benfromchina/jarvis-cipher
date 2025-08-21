package com.stark.jarvis.cipher.sm.verifier;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;
import com.stark.jarvis.cipher.core.verifier.AbstractVerifier;
import com.tencent.kona.KonaProvider;

import java.security.PublicKey;
import java.security.Security;

/**
 * 国密SM2验签器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class SM2Verifier extends AbstractVerifier {

    static {
        Security.addProvider(new KonaProvider());
    }

    public SM2Verifier(PublicKey publicKey) {
        super(AsymmetricAlgorithm.SM2, publicKey);
    }

}

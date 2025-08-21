package com.stark.jarvis.cipher.sm.signer;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;
import com.stark.jarvis.cipher.core.signer.AbstractSigner;
import com.tencent.kona.KonaProvider;

import java.security.PrivateKey;
import java.security.Security;

/**
 * 国密SM2签名器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class SM2Signer extends AbstractSigner {

    static {
        Security.addProvider(new KonaProvider());
    }

    public SM2Signer(PrivateKey privateKey) {
        super(AsymmetricAlgorithm.SM2, privateKey);
    }

}

package com.stark.jarvis.cipher.sm.privacy;

import com.stark.jarvis.cipher.core.privacy.AbstractPrivacyDecryptor;
import com.tencent.kona.KonaProvider;

import java.security.PrivateKey;
import java.security.Security;

/**
 * 国密SM2敏感数据解密器
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public final class SM2PrivacyDecryptor extends AbstractPrivacyDecryptor {

    static {
        Security.addProvider(new KonaProvider());
    }

    public SM2PrivacyDecryptor(PrivateKey privateKey) {
        super("SM2", privateKey);
    }

}

package com.stark.jarvis.cipher;

import com.stark.jarvis.cipher.signer.SM2Signer;
import com.stark.jarvis.cipher.signer.Signer;
import com.stark.jarvis.cipher.verifier.SM2Verifier;
import com.stark.jarvis.cipher.verifier.Verifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.stark.jarvis.cipher.TestConfig.CLIENT_PRIVATE_KEY_SM2_STRING;
import static com.stark.jarvis.cipher.TestConfig.CLIENT_PUBLIC_KEY_SM2_STRING;

public class SM2SignerTest {

    private static Signer sm2Signer;

    private static Verifier sm2Verifier;

    private static final String MESSAGE = "message";

    @BeforeAll
    public static void init() {
        sm2Signer = new SM2Signer(SMPemUtils.loadPrivateKeyFromString(CLIENT_PRIVATE_KEY_SM2_STRING));
        sm2Verifier = new SM2Verifier(SMPemUtils.loadPublicKeyFromString(CLIENT_PUBLIC_KEY_SM2_STRING));
    }

    @Test
    public void testSignThenVerify() {
        String signature = sm2Signer.sign(MESSAGE);
        Assertions.assertNotNull(signature);
        Assertions.assertTrue(sm2Verifier.verify(MESSAGE, signature));
    }

}

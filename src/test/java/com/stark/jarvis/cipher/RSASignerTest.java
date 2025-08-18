package com.stark.jarvis.cipher;

import com.stark.jarvis.cipher.signer.RSASigner;
import com.stark.jarvis.cipher.signer.Signer;
import com.stark.jarvis.cipher.verifier.RSAVerifier;
import com.stark.jarvis.cipher.verifier.Verifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.stark.jarvis.cipher.TestConfig.CLIENT_PRIVATE_KEY;
import static com.stark.jarvis.cipher.TestConfig.CLIENT_PUBLIC_KEY;

public class RSASignerTest {

    private static Signer rsaSigner;

    private static Verifier rsaVerifier;

    @BeforeAll
    public static void init() {
        rsaSigner = new RSASigner(CLIENT_PRIVATE_KEY);
        rsaVerifier = new RSAVerifier(CLIENT_PUBLIC_KEY);
    }

    @Test
    public void testSign() {
        String message = "message";
        String signature = rsaSigner.sign(message);
        Assertions.assertTrue(rsaVerifier.verify(message, signature));
    }

    @Test
    public void testGetAlgorithm() {
        Assertions.assertEquals("SHA256-RSA2048", rsaSigner.getAlgorithm());
    }

}

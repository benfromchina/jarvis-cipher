package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.AsymmetricAlgorithm;
import com.stark.jarvis.cipher.core.signer.Signer;
import com.stark.jarvis.cipher.core.verifier.Verifier;
import com.stark.jarvis.cipher.rsa.signer.RSASigner;
import com.stark.jarvis.cipher.rsa.verifier.RSAVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.stark.jarvis.cipher.rsa.TestConfig.CLIENT_PRIVATE_KEY;
import static com.stark.jarvis.cipher.rsa.TestConfig.CLIENT_PUBLIC_KEY;

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
        Assertions.assertEquals(AsymmetricAlgorithm.RSA.getName(), rsaSigner.getAlgorithm());
    }

}

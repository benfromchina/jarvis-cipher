package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.privacy.PrivacyDecryptor;
import com.stark.jarvis.cipher.core.privacy.PrivacyEncryptor;
import com.stark.jarvis.cipher.rsa.privacy.RSAPrivacyDecryptor;
import com.stark.jarvis.cipher.rsa.privacy.RSAPrivacyEncryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.stark.jarvis.cipher.rsa.TestConfig.CLIENT_PRIVATE_KEY;
import static com.stark.jarvis.cipher.rsa.TestConfig.CLIENT_PUBLIC_KEY;

public class RSAPrivacyTest {

    private static PrivacyEncryptor rsaPrivacyEncryptor;

    private static PrivacyDecryptor rsaPrivacyDecryptor;

    private static final String PLAINTEXT = "plaintext";

    @BeforeAll
    public static void init() {
        rsaPrivacyEncryptor = new RSAPrivacyEncryptor(CLIENT_PUBLIC_KEY);
        rsaPrivacyDecryptor = new RSAPrivacyDecryptor(CLIENT_PRIVATE_KEY);
    }

    @Test
    public void testEncryptThenDecryptWithOAEP() {
        String ciphertext = rsaPrivacyEncryptor.encrypt(PLAINTEXT);
        String decryptMessage = rsaPrivacyDecryptor.decrypt(ciphertext);
        Assertions.assertEquals(PLAINTEXT, decryptMessage);
    }

    @Test
    public void testEncryptTooLargePlaintext() {
        int paddingLen = 2 * 20 + 2; // OAEP adds 2 * sha1's length + 2 padding
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> rsaPrivacyEncryptor.encrypt(new String(new char[256 - paddingLen + 1])));
    }

}

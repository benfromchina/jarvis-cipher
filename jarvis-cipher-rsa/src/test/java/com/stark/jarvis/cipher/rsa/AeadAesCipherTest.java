package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.aead.AeadCipher;
import com.stark.jarvis.cipher.rsa.aead.AeadAesCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.stark.jarvis.cipher.rsa.TestConfig.AEAD_KEY;

public class AeadAesCipherTest {

    private static final String MESSAGE = "message";

    private static final String ASSOCIATED_DATA = "associatedData";

    private static final String NONCE = "uluk4a9R25RW";

    private static AeadCipher aeadAesCipher;

    @BeforeAll
    public static void init() {
        aeadAesCipher = new AeadAesCipher(AEAD_KEY.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptThenDecrypt() {
        String ciphertext = aeadAesCipher.encrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                MESSAGE.getBytes(StandardCharsets.UTF_8));
        String plaintext = aeadAesCipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(ciphertext));
        Assertions.assertEquals(MESSAGE, plaintext);
    }

}
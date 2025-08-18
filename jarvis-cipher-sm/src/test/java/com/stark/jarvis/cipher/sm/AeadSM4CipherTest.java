package com.stark.jarvis.cipher.sm;

import com.stark.jarvis.cipher.core.aead.AeadCipher;
import com.stark.jarvis.cipher.sm.aead.AeadSM4Cipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.stark.jarvis.cipher.sm.TestConfig.AEAD_KEY;

public class AeadSM4CipherTest {

    private static final String PLAINTEXT = "plaintext";

    private static final String ASSOCIATED_DATA = "associatedData";

    private static final String NONCE = "uluk4a9R25RW";

    private static AeadCipher sm4Cipher;

    @BeforeAll
    public static void init() {
        sm4Cipher = new AeadSM4Cipher(AEAD_KEY.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptThenDecrypt() {
        String encryptData = sm4Cipher.encrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        String decryptData = sm4Cipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(encryptData));
        Assertions.assertEquals(PLAINTEXT, decryptData);
    }

}

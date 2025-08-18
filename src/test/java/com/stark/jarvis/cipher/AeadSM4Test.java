package com.stark.jarvis.cipher;

import com.stark.jarvis.cipher.aead.AeadCipher;
import com.stark.jarvis.cipher.aead.AeadSM4Cipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AeadSM4Test {

    private static final String PLAINTEXT = "plaintext";

    private static final String ASSOCIATED_DATA = "associatedData";

    private static final String NONCE = "uluk4a9R25RW";

    private static final String CIPHERTEXT = "+lcLNfkZQQx+iQm20Apa3x9Mb/5L7PgZ7w==";

    private static final String VPP_KEY = "a7cde1ZJB1kG2e7VfTs3jQzaWizur8Gb";

    private static AeadCipher sm4Cipher;

    @BeforeAll
    public static void init() {
        sm4Cipher = new AeadSM4Cipher(VPP_KEY.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testEncrypt() {
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

    @Test
    public void testDecrypt() {
        String result = sm4Cipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(CIPHERTEXT));
        Assertions.assertEquals(PLAINTEXT, result);
    }

    @Test
    public void testDecryptFail() {
        Assertions.assertThrows(DecryptionException.class, () -> sm4Cipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode("+lcLNfkZQQx+iQm20Apa3x9Mb/5L7PgZ8w==")));
    }

}

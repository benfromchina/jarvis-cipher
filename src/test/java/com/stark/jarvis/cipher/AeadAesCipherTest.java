package com.stark.jarvis.cipher;

import com.stark.jarvis.cipher.aead.AeadAesCipher;
import com.stark.jarvis.cipher.aead.AeadCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.stark.jarvis.cipher.TestConfig.AEAD_KEY;

public class AeadAesCipherTest {

    private static final String MESSAGE = "message";

    private static final String ASSOCIATED_DATA = "associatedData";

    private static final String NONCE = "uluk4a9R25RW";

    private static final String CIPHERTEXT = "ulwSiIajGClcvcOYvOQ7+l+0PAbzzwI=";

    private static AeadCipher aeadAesCipher;

    @BeforeAll
    public static void init() {
        aeadAesCipher = new AeadAesCipher(AEAD_KEY.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptToString() {
        String ciphertext = aeadAesCipher.encrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                MESSAGE.getBytes(StandardCharsets.UTF_8));
        Assertions.assertEquals(CIPHERTEXT, ciphertext);
    }

    @Test
    public void testDecryptToString() {
        String plaintext = aeadAesCipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(CIPHERTEXT));
        Assertions.assertEquals(MESSAGE, plaintext);
    }

    @Test
    public void testDecryptBadAAD() {
        Assertions.assertThrows(DecryptionException.class, () -> aeadAesCipher.decrypt(
                "bad-associatedData".getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(CIPHERTEXT)));
    }

    @Test
    public void testDecryptBadNonce() {
        Assertions.assertThrows(DecryptionException.class, () -> aeadAesCipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                "bad-4a9R25RW".getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(CIPHERTEXT)));
    }

    @Test
    public void testDecryptBadCipher() {
        Assertions.assertThrows(DecryptionException.class, () -> aeadAesCipher.decrypt(
                ASSOCIATED_DATA.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8),
                new byte[128]));
    }

}
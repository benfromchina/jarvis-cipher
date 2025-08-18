package com.stark.jarvis.cipher;

import com.stark.jarvis.cipher.privacy.PrivacyDecryptor;
import com.stark.jarvis.cipher.privacy.PrivacyEncryptor;
import com.stark.jarvis.cipher.privacy.SM2PrivacyDecryptor;
import com.stark.jarvis.cipher.privacy.SM2PrivacyEncryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.stark.jarvis.cipher.TestConfig.CLIENT_PRIVATE_KEY_SM2;
import static com.stark.jarvis.cipher.TestConfig.CLIENT_PUBLIC_KEY_SM2;

public class SM2PrivacyTest {

    private static PrivacyEncryptor sm2PrivacyEncryptor;

    private static PrivacyDecryptor sm2PrivacyDecryptor;

    @BeforeAll
    public static void init() {
        sm2PrivacyEncryptor = new SM2PrivacyEncryptor(CLIENT_PUBLIC_KEY_SM2);
        sm2PrivacyDecryptor = new SM2PrivacyDecryptor(CLIENT_PRIVATE_KEY_SM2);
    }

    @Test
    public void testEncryptThenDecrypt() {
        String plaintext = "plaintext";
        String ciphertext = sm2PrivacyEncryptor.encrypt(plaintext);
        Assertions.assertEquals(plaintext, sm2PrivacyDecryptor.decrypt(ciphertext));
    }

}

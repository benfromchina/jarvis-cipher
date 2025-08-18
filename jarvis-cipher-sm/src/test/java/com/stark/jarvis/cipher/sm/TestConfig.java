package com.stark.jarvis.cipher.sm;

import com.stark.jarvis.cipher.core.IOUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestConfig {

    public static final String RESOURCES_DIR;

    public static final String CLIENT_PRIVATE_KEY_SM2_PATH;

    public static final String CLIENT_PUBLIC_KEY_SM2_PATH;

    public static final String CLIENT_PRIVATE_KEY_SM2_STRING;

    public static final PrivateKey CLIENT_PRIVATE_KEY_SM2;

    public static final String CLIENT_PUBLIC_KEY_SM2_STRING;

    public static final PublicKey CLIENT_PUBLIC_KEY_SM2;

    public static final String AEAD_KEY = "a7cde1ZJB1kG2e7VfTs3jQzaWizur8Gb";

    static {
        try {
            RESOURCES_DIR = System.getProperty("user.dir") + "/src/test/resources";
            CLIENT_PRIVATE_KEY_SM2_PATH = RESOURCES_DIR + "/client_private_key_sm2.pem";
            CLIENT_PRIVATE_KEY_SM2_STRING = IOUtils.loadStringFromPath(CLIENT_PRIVATE_KEY_SM2_PATH);
            CLIENT_PRIVATE_KEY_SM2 = SMPemUtils.loadPrivateKeyFromString(CLIENT_PRIVATE_KEY_SM2_STRING);
            CLIENT_PUBLIC_KEY_SM2_PATH = RESOURCES_DIR + "/client_public_key_sm2.pem";
            CLIENT_PUBLIC_KEY_SM2_STRING = IOUtils.loadStringFromPath(CLIENT_PUBLIC_KEY_SM2_PATH);
            CLIENT_PUBLIC_KEY_SM2 = SMPemUtils.loadPublicKeyFromString(CLIENT_PUBLIC_KEY_SM2_STRING);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}

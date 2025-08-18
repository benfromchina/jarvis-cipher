package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.IOUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestConfig {

    public static final String RESOURCES_DIR;

    public static final String CLIENT_PRIVATE_KEY_PATH;

    public static final String CLIENT_PUBLIC_KEY_PATH;

    public static final String CLIENT_PRIVATE_KEY_STRING;

    public static final PrivateKey CLIENT_PRIVATE_KEY;

    public static final String CLIENT_PUBLIC_KEY_STRING;

    public static final PublicKey CLIENT_PUBLIC_KEY;

    public static final String AEAD_KEY = "a7cde1ZJB1kG2e7VfTs3jQzaWizur8Gb";

    static {
        try {
            RESOURCES_DIR = System.getProperty("user.dir") + "/src/test/resources";
            CLIENT_PRIVATE_KEY_PATH = RESOURCES_DIR + "/client_private_key.pem";
            CLIENT_PRIVATE_KEY_STRING = IOUtils.loadStringFromPath(CLIENT_PRIVATE_KEY_PATH);
            CLIENT_PRIVATE_KEY = RSAPemUtils.loadPrivateKeyFromString(CLIENT_PRIVATE_KEY_STRING);
            CLIENT_PUBLIC_KEY_PATH = RESOURCES_DIR + "/client_public_key.pem";
            CLIENT_PUBLIC_KEY_STRING = IOUtils.loadStringFromPath(CLIENT_PUBLIC_KEY_PATH);
            CLIENT_PUBLIC_KEY = RSAPemUtils.loadPublicKeyFromString(CLIENT_PUBLIC_KEY_STRING);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}

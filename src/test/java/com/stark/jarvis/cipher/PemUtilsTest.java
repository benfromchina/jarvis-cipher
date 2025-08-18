package com.stark.jarvis.cipher;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class PemUtilsTest {

    @Test
    public void testSign() throws Exception {
        KeyPair caKeyPair = PemUtils.createKeyPair();
        SubjectInfo subjectInfo = new SubjectInfo()
                .setCommonName("Eastsoft EMS ROOT CA")
                .setOrganizationalUnit("Eastsoft EMS Certificate Authority")
                .setOrganization("Eastsoft EMS")
                .setLocality("Qingdao")
                .setStateOrProvince("Shandong")
                .setCountry("CN");
        X509Certificate rootCert = PemUtils.createRootCert(
                caKeyPair,
                subjectInfo,
                BigInteger.valueOf(System.currentTimeMillis()),
                10);

        KeyPair clientKeyPair = PemUtils.createKeyPair();
        subjectInfo = new SubjectInfo()
                .setCommonName("CLIENT EMS");
        X509Certificate clientCert = PemUtils.issueClientCert(
                rootCert,
                caKeyPair.getPrivate(),
                clientKeyPair.getPublic(),
                subjectInfo,
                BigInteger.valueOf(System.currentTimeMillis()),
                1);

        PemUtils.verifyCert(clientCert, rootCert);

        /*
        String caCertPem = PemUtils.certToPEM(rootCert);
        String caPublicKeyPem = PemUtils.publicKeyToPEM(rootCert.getPublicKey());
        String caPrivatePem = PemUtils.privateKeyToPEM(caKeyPair.getPrivate());
        String clientCertPem = PemUtils.certToPEM(clientCert);
        String clientPublicKeyPem = PemUtils.publicKeyToPEM(clientCert.getPublicKey());
        String clientPrivatePem = PemUtils.privateKeyToPEM(clientKeyPair.getPrivate());
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_crt.pem"), caCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_public_key.pem"), caPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_private_key.pem"), caPrivatePem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_crt.pem"), clientCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_public_key.pem"), clientPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_private_key.pem"), clientPrivatePem.getBytes(StandardCharsets.UTF_8));
        */
    }

}

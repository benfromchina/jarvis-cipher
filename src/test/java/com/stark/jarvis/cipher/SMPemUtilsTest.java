package com.stark.jarvis.cipher;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class SMPemUtilsTest {

    @Test
    public void testSign() throws Exception {
        KeyPair caKeyPair = SMPemUtils.createKeyPair();
        SubjectInfo subjectInfo = new SubjectInfo()
                .setCommonName("Eastsoft EMS ROOT CA")
                .setOrganizationalUnit("Eastsoft EMS Certificate Authority")
                .setOrganization("Eastsoft EMS")
                .setLocality("Qingdao")
                .setStateOrProvince("Shandong")
                .setCountry("CN");
        X509Certificate rootCert = SMPemUtils.createRootCert(
                caKeyPair,
                subjectInfo,
                BigInteger.valueOf(System.currentTimeMillis()),
                10);

        KeyPair clientKeyPair = SMPemUtils.createKeyPair();
        subjectInfo = new SubjectInfo()
                .setCommonName("CLIENT EMS");
        X509Certificate clientCert = SMPemUtils.issueClientCert(
                rootCert,
                caKeyPair.getPrivate(),
                clientKeyPair.getPublic(),
                subjectInfo,
                BigInteger.valueOf(System.currentTimeMillis()),
                1);

        SMPemUtils.verifyCert(clientCert, rootCert);

        System.out.println("-->" + caKeyPair.getPrivate().getAlgorithm());

        /*
        String caCertPem = SMPemUtils.certToPEM(rootCert);
        String caPublicKeyPem = SMPemUtils.publicKeyToPEM(rootCert.getPublicKey());
        String caPrivatePem = SMPemUtils.privateKeyToPEM(caKeyPair.getPrivate());
        String clientCertPem = SMPemUtils.certToPEM(clientCert);
        String clientPublicKeyPem = SMPemUtils.publicKeyToPEM(clientCert.getPublicKey());
        String clientPrivatePem = SMPemUtils.privateKeyToPEM(clientKeyPair.getPrivate());
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_crt_sm2.pem"), caCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_public_key_sm2.pem"), caPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_private_key_sm2.pem"), caPrivatePem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_crt_sm2.pem"), clientCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_public_key_sm2.pem"), clientPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_private_key_sm2.pem"), clientPrivatePem.getBytes(StandardCharsets.UTF_8));
        */
    }

}

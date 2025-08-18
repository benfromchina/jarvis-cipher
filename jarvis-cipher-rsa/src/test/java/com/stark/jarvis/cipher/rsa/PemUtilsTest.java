package com.stark.jarvis.cipher.rsa;

import com.stark.jarvis.cipher.core.SubjectInfo;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class PemUtilsTest {

    @Test
    public void testSign() throws Exception {
        KeyPair caKeyPair = RSAPemUtils.createKeyPair();
        SubjectInfo subjectInfo = new SubjectInfo()
                .setCommonName("Eastsoft EMS ROOT CA")
                .setOrganizationalUnit("Eastsoft EMS Certificate Authority")
                .setOrganization("Eastsoft EMS")
                .setLocality("Qingdao")
                .setStateOrProvince("Shandong")
                .setCountry("CN");
        X509Certificate rootCert = RSAPemUtils.createRootCert(
                caKeyPair,
                BigInteger.valueOf(System.currentTimeMillis()),
                subjectInfo,
                10);

        KeyPair clientKeyPair = RSAPemUtils.createKeyPair();
        subjectInfo = new SubjectInfo()
                .setCommonName("CLIENT EMS");
        X509Certificate clientCert = RSAPemUtils.issueClientCert(
                rootCert,
                caKeyPair.getPrivate(),
                clientKeyPair.getPublic(),
                BigInteger.valueOf(System.currentTimeMillis()),
                subjectInfo,
                1);

        RSAPemUtils.verifyCert(clientCert, rootCert);

        /*
        String caCertPem = RSAPemUtils.certToPEM(rootCert);
        String caPublicKeyPem = RSAPemUtils.publicKeyToPEM(rootCert.getPublicKey());
        String caPrivatePem = RSAPemUtils.privateKeyToPEM(caKeyPair.getPrivate());
        String clientCertPem = RSAPemUtils.certToPEM(clientCert);
        String clientPublicKeyPem = RSAPemUtils.publicKeyToPEM(clientCert.getPublicKey());
        String clientPrivatePem = RSAPemUtils.privateKeyToPEM(clientKeyPair.getPrivate());
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_crt.pem"), caCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_public_key.pem"), caPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/ca_private_key.pem"), caPrivatePem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_crt.pem"), clientCertPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_public_key.pem"), clientPublicKeyPem.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("/Users/Ben/Desktop/test/client_private_key.pem"), clientPrivatePem.getBytes(StandardCharsets.UTF_8));
        */
    }

}

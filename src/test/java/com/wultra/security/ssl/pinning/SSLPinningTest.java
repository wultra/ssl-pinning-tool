package com.wultra.security.ssl.pinning;

import com.google.common.io.BaseEncoding;
import com.wultra.security.ssl.pinning.errorhandling.SSLPinningException;
import com.wultra.security.ssl.pinning.model.CertificateInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.*;

class SSLPinningTest {

    private Application app;
    private File keyPairFile;

    private static final String PRIVATE_KEY_PASSWORD = "s3cret";
    private static final String TEST_CERTIFICATE_BASE64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR4ekNDQXErZ0F3SUJBZ0lJZkd4NURBK3VZS1F3RFFZSktvWklodmNOQVFFTEJRQXdWREVMTUFrR0ExVUUKQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFbE1DTUdBMVVFQXhNYwpSMjl2WjJ4bElFbHVkR1Z5Ym1WMElFRjFkR2h2Y21sMGVTQkhNekFlRncweE9EQTRNVFF3TnpRME16VmFGdzB4Ck9ERXdNak13TnpNNE1EQmFNR2d4Q3pBSkJnTlZCQVlUQWxWVE1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGgKTVJZd0ZBWURWUVFIREExTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtEQXBIYjI5bmJHVWdURXhETVJjdwpGUVlEVlFRRERBNTNkM2N1WjI5dloyeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBCkJORVVBazlkQm5kTHJkci9FV01aWlI2NHZZOXVUdWNkUWM3Ymp4U0lESXFYZCtyVlhRdFg5VzRxZmh5eDhFVHgKZUZ0ZDltLy9QV3M2TDFYS3JlcWdaa0dqZ2dGU01JSUJUakFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQVRBTwpCZ05WSFE4QkFmOEVCQU1DQjRBd0dRWURWUjBSQkJJd0VJSU9kM2QzTG1kdmIyZHNaUzVqYjIwd2FBWUlLd1lCCkJRVUhBUUVFWERCYU1DMEdDQ3NHQVFVRkJ6QUNoaUZvZEhSd09pOHZjR3RwTG1kdmIyY3ZaM055TWk5SFZGTkgKU1VGSE15NWpjblF3S1FZSUt3WUJCUVVITUFHR0hXaDBkSEE2THk5dlkzTndMbkJyYVM1bmIyOW5MMGRVVTBkSgpRVWN6TUIwR0ExVWREZ1FXQkJRZlQxUjFJUVVyc05NVjhFdEd5M2wvcmNPMDF6QU1CZ05WSFJNQkFmOEVBakFBCk1COEdBMVVkSXdRWU1CYUFGSGZDdUZDYVozWjJzUzNDaHRDRG9INm1mcnBMTUNFR0ExVWRJQVFhTUJnd0RBWUsKS3dZQkJBSFdlUUlGQXpBSUJnWm5nUXdCQWdJd01RWURWUjBmQkNvd0tEQW1vQ1NnSW9ZZ2FIUjBjRG92TDJOeQpiQzV3YTJrdVoyOXZaeTlIVkZOSFNVRkhNeTVqY213d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJWmlXM2pXCm1zOUJ5a0NZUDN1Z2haMDJ2ZE4xZ3dnWmtYa281eVh6TUhyMWtzem5nRFlZLzYrRlB0RHBNb0YwbW4yZ0ZkR1IKK1Z2RUFMaTlLaW95M2s0T0dOaEFtd0NHR2JEelNqYlRIK3dPUHZpdnFPR3lMRUpTbzREeGlqNHZPUU9ENlRUYQpKREhrT0Q3OVFFY3VqRlRjM3lEZzMvZ0M0Tm14dm14SEZ0UlNmenJxSUQ3VG9tTmVyL2NFSE1tTytFRWl6YlR1CjU2L2xiVVpqQ3dkNzB3aFFNZ0wwNWpneXdOWUpVay8waUhZd0JGbjhDRWU1QVlBR3FMeThGYWJDZ2ZSbmFzeW4KTGRSZTRoMU1NaFdvT0toSTdueVNvL3NlS3k5OFRhd0RFczdjcTZwR3ovR1h6RWdYQmVVU1ZEU0lURkM1MFRPVQpEZnFYS3Bpa2Z0MzN5TTg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K";

    @BeforeEach
    void setUp() throws IOException, CryptoProviderException {
        app = new Application();
        keyPairFile = File.createTempFile("ssl_pinning", ".pem");
        app.generateKeyPair(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD);
    }

    @AfterEach
    void tearDown() {
        assertTrue(keyPairFile.delete());
    }

    @Test
    void testBCProvider() {
        assertNotNull(Security.getProvider("BC"));
    }

    @Test
    void testGenerateKeyPairCorrectPassword() throws SSLPinningException {
        assertNotNull(app.loadPrivateKey(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD));
    }

    @Test
    void testGenerateKeyPairInvalidPassword() {
        assertThrows(SSLPinningException.class, ()-> app.loadPrivateKey(keyPairFile.getAbsolutePath(), "invalid"));
    }

    @Test
    void testSignatureWithDetails() throws SSLPinningException, InvalidKeyException, GenericCryptoException, CryptoProviderException {
        CertificateInfo certInfo = app.sign(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD,
                "www.google.com", "9eed43381cf7d58e4563a951364255fc776707a043542a7b997d27c646ee6fb6", 1540280280L);
        byte[] signature = BaseEncoding.base64().decode(certInfo.getSignature());
        PublicKey publicKey = app.exportPublicKey(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD);
        String payload = "www.google.com&nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=&1540280280";
        final SignatureUtils utils = new SignatureUtils();
        assertTrue(utils.validateECDSASignature(payload.getBytes(), signature, publicKey));
    }

    @Test
    void testSignatureWithCertInfo() throws SSLPinningException, SignatureException, InvalidKeyException, GenericCryptoException, CryptoProviderException {
        CertificateInfo certInfoIn = new CertificateInfo();
        certInfoIn.setName("www.google.com");
        certInfoIn.setExpires(1540280280L);
        certInfoIn.setFingerprint("9eed43381cf7d58e4563a951364255fc776707a043542a7b997d27c646ee6fb6");
        CertificateInfo certInfo = app.sign(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD, certInfoIn);
        byte[] signature = BaseEncoding.base64().decode(certInfo.getSignature());
        PublicKey publicKey = app.exportPublicKey(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD);
        String payload = "www.google.com&nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=&1540280280";
        final SignatureUtils utils = new SignatureUtils();
        assertTrue(utils.validateECDSASignature(payload.getBytes(), signature, publicKey));
    }

    @Test
    void testReadCertificate() throws IOException, SSLPinningException {
        File cerFile = File.createTempFile("ssl_pinning", ".cer");
        FileWriter fw = new FileWriter(cerFile.getAbsolutePath());
        fw.write(new String(BaseEncoding.base64().decode(TEST_CERTIFICATE_BASE64)));
        fw.close();
        CertificateInfo certInfo = app.readCertificateInfo(cerFile.getAbsolutePath());
        assertEquals("www.google.com", certInfo.getName());
        assertEquals(1540280280L, certInfo.getExpires());
        assertEquals("9eed43381cf7d58e4563a951364255fc776707a043542a7b997d27c646ee6fb6", certInfo.getFingerprint());
        assertTrue(cerFile.delete());
    }

    @Test
    void testGenerateJsonFile() throws IOException, SSLPinningException, InvalidKeyException, GenericCryptoException, CryptoProviderException {
        File jsonFile = File.createTempFile("ssl_pinning", ".json");
        File cerFile = File.createTempFile("ssl_pinning", ".cer");
        FileWriter fw = new FileWriter(cerFile.getAbsolutePath());
        fw.write(new String(BaseEncoding.base64().decode(TEST_CERTIFICATE_BASE64)));
        fw.close();
        CertificateInfo certInfoIn = app.readCertificateInfo(cerFile.getAbsolutePath());
        CertificateInfo certInfo = app.sign(keyPairFile.getAbsolutePath(), PRIVATE_KEY_PASSWORD, certInfoIn);
        app.generateJsonFile(jsonFile.getAbsolutePath(), certInfo);
        Scanner scanner = new Scanner(new File(jsonFile.getAbsolutePath()));
        scanner.useDelimiter("\\Z");
        String generatedJson = scanner.next();
        scanner.close();
        // replace current signature with static string, it is always different
        generatedJson = generatedJson.replace(certInfo.getSignature(), "SIGNATURE");
        assertEquals("{\n" +
                "  \"name\" : \"www.google.com\",\n" +
                "  \"fingerprint\" : \"nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=\",\n" +
                "  \"expires\" : 1540280280,\n" +
                "  \"signature\" : \"SIGNATURE\"\n" +
                "}", generatedJson);
        assertTrue(cerFile.delete());
        assertTrue(jsonFile.delete());
    }

}

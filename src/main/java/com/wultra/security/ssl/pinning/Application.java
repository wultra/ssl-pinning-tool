/*
 * Copyright 2018 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wultra.security.ssl.pinning;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.wultra.security.ssl.pinning.errorhandling.SSLPinningException;
import com.wultra.security.ssl.pinning.model.CertificateInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * SSL pinning tool command line application for generating signatures of SSL certificates.
 */
public class Application {

    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    private static final ASN1ObjectIdentifier PASSWORD_ENCRYPTION_ALGORITHM = PKCS8Generator.AES_128_CBC;
    private static final AlgorithmIdentifier PASSWORD_ENCRYPTION_PRF = PKCS8Generator.PRF_HMACSHA256;

    Application() {
        // Enable one-line logging
        System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT - %4$s %5$s%6$s%n");

        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Main entry point.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) {
        final Application app = new Application();

        final CommandLine cmd = app.prepareCommandLine(args);
        if (cmd == null) {
            return;
        }

        app.executeCommand(cmd);
    }

    /**
     * Execute command based on command line options.
     *
     * @param cmd CommandLine instance.
     */
    private void executeCommand(CommandLine cmd) {
        // Read configuration
        final String privateKeyPath = cmd.getOptionValue("k");
        final String outputPath = cmd.getOptionValue("o");
        final String commonName = cmd.getOptionValue("n");
        final String certificatePath = cmd.getOptionValue("c");
        final String fingerprint = cmd.getOptionValue("f");
        final String expires = cmd.getOptionValue("t");
        final String privateKeyPassword = cmd.getOptionValue("p");

        Long expirationTime = null;

        if (expires != null) {
            try {
                expirationTime = Long.parseLong(expires);
            } catch (NumberFormatException ex) {
                logger.error(ex.getMessage(), ex);
                return;
            }
        }

        final String command = cmd.getArgList().get(0);

        switch (command) {
            case "sign":
                // Sign fingerprint data
                try {
                    if (privateKeyPath == null) {
                        logger.error("Private key path is not specified, cannot compute signature.");
                        return;
                    }
                    if (outputPath == null) {
                        logger.error("Output path is not specified, cannot generate JSON file.");
                        return;
                    }
                    if (certificatePath == null && commonName == null) {
                        logger.error("Common name is not specified, cannot compute signature.");
                        return;
                    }
                    if (certificatePath == null && fingerprint == null) {
                        logger.error("Fingerprint is not specified, cannot compute signature.");
                        return;
                    }
                    if (certificatePath == null && expirationTime == null) {
                        logger.error("Expiration time is not specified, cannot compute signature.");
                        return;
                    }
                    if (certificatePath != null && (commonName != null || fingerprint != null && expirationTime != null)) {
                        logger.error("Ambiguous certificate data found, cannot compute signature.");
                        return;
                    }
                    final CertificateInfo signedFingerprint;
                    if (certificatePath != null) {
                        final CertificateInfo certInfo = readCertificateInfo(certificatePath);
                        signedFingerprint = sign(privateKeyPath, privateKeyPassword, certInfo);
                    } else {
                        signedFingerprint = sign(privateKeyPath, privateKeyPassword, commonName, fingerprint, expirationTime);
                    }
                    generateJsonFile(outputPath, signedFingerprint);
                } catch (Exception ex) {
                    logger.error(ex.getMessage(), ex);
                }
                break;

            case "keygen":
                // Generate keypair
                try {
                    if (outputPath == null) {
                        logger.error("Output path is not specified, cannot generate key pair.");
                        return;
                    }
                    generateKeyPair(outputPath, privateKeyPassword);
                } catch (Exception ex) {
                    logger.error(ex.getMessage(), ex);
                }
                break;

            case "export":
                // Export public key
                try {
                    if (privateKeyPath == null) {
                        logger.error("Private key path is not specified, cannot export public key.");
                        return;
                    }
                    final PublicKey publicKey = exportPublicKey(privateKeyPath, privateKeyPassword);
                    printPublicKey(publicKey);
                } catch (Exception ex) {
                    logger.error(ex.getMessage(), ex);
                }
                break;

            case "export-private":
                // Export public key
                try {
                    if (privateKeyPath == null) {
                        logger.error("Private key path is not specified, cannot export public key.");
                        return;
                    }
                    final PrivateKey privateKey = exportPrivateKey(privateKeyPath, privateKeyPassword);
                    printPrivateKey(privateKey);
                } catch (Exception ex) {
                    logger.error(ex.getMessage(), ex);
                }
                break;
            default:
                // Unknown action
                logger.error("Unknown command: " + command);
        }
    }

    /**
     * Prepare command line object.
     * @param args Command line arguments.
     * @return Command line object.
     */
    private CommandLine prepareCommandLine(String[] args) {
        // Parse options
        final Options options = buildOptions();

        // Prepare command line
        final CommandLine cmd;
        try {
            final CommandLineParser parser = new DefaultParser();
            cmd = parser.parse(options, args);
            // Print options when user specified no options or help was invoked
            if (args.length == 0 || cmd.hasOption("h")) {
                final HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(100);
                formatter.printHelp("java -jar ssl-pinning-tool.jar", options);
                return null;
            }
        } catch (ParseException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        }
        return cmd;
    }

    /**
     * Build command line options.
     * @return Command line options.
     */
    private Options buildOptions() {
        // Options definition
        final Options options = new Options();
        options.addOption("h", "help", false, "Print this help manual.");
        options.addOption("k", "key", true, "EC private key in PEM format stored as PKCS #8.");
        options.addOption("p", "password", true, "Password for encrypted private key file.");
        options.addOption("o", "output", true, "Output file.");
        options.addOption("c", "certificate", true, "SSL certificate in PEM format.");
        options.addOption("n", "name", true, "Domain common name.");
        options.addOption("f", "fingerprint", true, "SHA-256 fingerprint of certificate in HEX format.");
        options.addOption("t", "expires", true, "Expiration time in Unix timestamp format.");
        options.addOption("g", "generate", true, "Generate EC key pair.");
        return options;
    }

    /**
     * Sign certificate details using private key.
     * @param privateKeyPath Path to private key file.
     * @param privateKeyPassword  Private key password (optional).
     * @param commonName Domain common name.
     * @param fingerprint SSL certificate SHA-256 fingerprint in HEX format.
     * @param expirationTime Expiration time as Unix timestamp.
     * @return Fingerprint object.
     * @throws SSLPinningException Thrown when encryption fails.
     * @throws InvalidKeyException Thrown when signature key is invalid.
     * @throws SSLPinningException Thrown when issue happens with SSL pinning data.
     */
    CertificateInfo sign(String privateKeyPath, String privateKeyPassword, String commonName, String fingerprint, long expirationTime)
            throws SSLPinningException, InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Load private key
        final PrivateKey privKey = loadPrivateKey(privateKeyPath, privateKeyPassword);

        // Remove all whitespaces from fingerprint
        final String fingerprintFormatted = fingerprint.replaceAll("\\s+", "");

        // Convert fingerprint to byte[]
        final byte[] fingerPrintBytes = Hex.decode(fingerprintFormatted);

        // Convert fingerprint bytes to Base64
        final String fingerprintBase64 = BaseEncoding.base64().encode(fingerPrintBytes);

        // Signature payload
        final String data = commonName + "&" + fingerprintBase64 + "&" + expirationTime;

        // Compute signature of payload using ECDSA with given EC private key
        final SignatureUtils utils = new SignatureUtils();
        final byte[] signature = utils.computeECDSASignature(data.getBytes(Charsets.UTF_8), privKey);
        final String signatureBase64 = BaseEncoding.base64().encode(signature);

        // Return Fingerprint object
        return new CertificateInfo(commonName, fingerprintBase64, expirationTime, signatureBase64);
    }

    /**
     * Sign certificate using private key.
     * @param privateKeyPath Path to private key.
     * @param privateKeyPassword Private key password (optional).
     * @param certInfo Information about certificate.
     * @return Signed certificate fingerprint.
     * @throws SSLPinningException Thrown when certificate fingerprint signature could not be computed.
     * @throws InvalidKeyException Thrown when private key is invalid.
     */
    CertificateInfo sign(String privateKeyPath, String privateKeyPassword, CertificateInfo certInfo) throws SSLPinningException, InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return sign(privateKeyPath, privateKeyPassword, certInfo.getName(), certInfo.getFingerprint(), certInfo.getExpires());
    }

    /**
     * Load private key from file.
     * @param privateKeyPath Path to file with private key in PEM format.
     * @param password Private key password (optional).
     * @return Private key.
     */
    PrivateKey loadPrivateKey(String privateKeyPath, String password) throws SSLPinningException {
        try (FileReader fileReader = new FileReader(privateKeyPath)) {
            final PEMParser pemParser = new PEMParser(new BufferedReader(fileReader));
            // Expected key type is EC
            final KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
            final Object pemInfo = pemParser.readObject();
            pemParser.close();
            if (pemInfo instanceof final PrivateKeyInfo privateKeyInfo) {
                // Private key is not encrypted
                if (password != null) {
                    throw new SSLPinningException("Private key is not encrypted, however private key password is specified.");
                }
                final byte[] privateKeyBytes = privateKeyInfo.getEncoded();
                final KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                return kf.generatePrivate(keySpec);
            } else if (pemInfo instanceof final PKCS8EncryptedPrivateKeyInfo pemPrivateKeyInfo) {
                // Private key is encrypted by password, decrypt it
                if (password == null) {
                    throw new SSLPinningException("Private key is encrypted, however private key password is missing.");
                }
                final InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
                final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(pemPrivateKeyInfo.decryptPrivateKeyInfo(provider));
            }
        } catch (Exception ex) {
            throw new SSLPinningException("Failed to load private key, error: " + ex.getMessage(), ex);

        }
        throw new SSLPinningException("Private key could not be loaded because of unknown format.");
    }

    /**
     * Load certificate from PEM file and return information relevant for certificate signature.
     * @param certificatePath Path to certificate file.
     * @return Information about certificate.
     * @throws SSLPinningException Thrown when certificate could not be loaded.
     */
    CertificateInfo readCertificateInfo(String certificatePath) throws SSLPinningException {
        try (FileReader fileReader = new FileReader(certificatePath)) {
            final PEMParser pemParser = new PEMParser(new BufferedReader(fileReader));
            final Object pemInfo = pemParser.readObject();
            pemParser.close();
            if (pemInfo instanceof final X509CertificateHolder x509Cert) {
                final CertificateInfo certInfo = new CertificateInfo();
                final byte[] signature = computeSHA256Signature(x509Cert.getEncoded());
                certInfo.setFingerprint(new String(Hex.encode(signature)));
                // Expiration timestamps is stored as unix timestamp with seconds
                certInfo.setExpires(x509Cert.getNotAfter().getTime()/1000);
                final X500Name x500Name = x509Cert.getSubject();
                final RDN commonNameRDN = x500Name.getRDNs(BCStyle.CN)[0];
                final String commonName = IETFUtils.valueToString(commonNameRDN.getFirst().getValue());
                certInfo.setName(commonName);
                return certInfo;
            }
        } catch (Exception ex) {
            throw new SSLPinningException("Failed to load certificate, error: " + ex.getMessage(), ex);

        }
        throw new SSLPinningException("Certificate could not be loaded because of unknown format.");
    }

    /**
     * Compute SHA-256 signature of certificate.
     * @param certificateData Raw certificate data.
     * @return SHA-256 signature of data.
     * @throws NoSuchAlgorithmException Thrown when SHA-256 algorithm is not supported.
     */
    private byte[] computeSHA256Signature(byte[] certificateData) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(certificateData);
        return md.digest();
    }

    /**
     * Generate EC key pair as PEM file.
     * @param outputPath Path to generated PEM file.
     * @param keyPairPassword Private key password (optional).
     * @throws IOException Thrown when key pair could not be generates.
     */
    void generateKeyPair(String outputPath, String keyPairPassword) throws CryptoProviderException, IOException {
        final KeyGenerator keyGen = new KeyGenerator();
        final KeyPair keyPair = keyGen.generateKeyPair();
        OutputEncryptor encryptor = null;
        // The getEncoded() method returns key in PKCS8 format, it can be either unencrypted or encrypted
        if (keyPairPassword != null) {
            // Password was specified, generate encrypted PEM file
            final JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PASSWORD_ENCRYPTION_ALGORITHM);
            encryptorBuilder.setProvider("BC");
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPasssword(keyPairPassword.toCharArray());
            encryptorBuilder.setPRF(PASSWORD_ENCRYPTION_PRF);
            try {
                encryptor = encryptorBuilder.build();
            } catch (OperatorCreationException ex) {
                // Failed to create encryptor, PEM file will not be encrypted
                logger.error("Failed to create encryptor, PEM file will not be encrypted. Error: {}", ex.getMessage(), ex);
            }
        }

        final PemObjectGenerator generator = new JcaPKCS8Generator(keyPair.getPrivate(), encryptor);

        // Generate PemObject using generator
        final PemObject pemObject = generator.generate();

        // Generate PEM file
        final FileWriter fw = new FileWriter(outputPath);
        try (PemWriter pemWriterPriv = new PemWriter(fw)) {
            pemWriterPriv.writeObject(pemObject);
            System.out.println("EC private key generated in file: " + outputPath);
        }
    }

    /**
     * Generate JSON file.
     *
     * @param outputPath  Output path.
     * @param fingerPrint Fingerprint with signature details.
     * @throws IOException Thrown when JSON file could not be generated.
     */
    void generateJsonFile(String outputPath, CertificateInfo fingerPrint) throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final FileWriter fw = new FileWriter(outputPath);
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.writeValue(fw, fingerPrint);
        fw.close();
        System.out.println("JSON output generated in file: " + outputPath);
    }

    /**
     * Convert EC private key to public key.
     * @param privateKeyPath Path to private key.
     * @param privateKeyPassword Private key password.
     * @throws SSLPinningException Thrown when export fails.
     */
    PublicKey exportPublicKey(String privateKeyPath, String privateKeyPassword) throws SSLPinningException {
        try {
            final PrivateKey privateKey = loadPrivateKey(privateKeyPath, privateKeyPassword);
            final KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            final ECPoint Q = ecSpec.getG().multiply(((ECPrivateKey) privateKey).getD());
            final ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
            return keyFactory.generatePublic(pubSpec);
        } catch (Exception ex) {
            throw new SSLPinningException("Failed to convert private key, error: " + ex.getMessage(), ex);
        }
    }

    /**
     * Load private key
     * @param privateKeyPath Path to private key.
     * @param privateKeyPassword Private key password.
     * @throws SSLPinningException Thrown when export fails.
     */
    PrivateKey exportPrivateKey(String privateKeyPath, String privateKeyPassword) throws SSLPinningException {
        try {
            return loadPrivateKey(privateKeyPath, privateKeyPassword);
        } catch (Exception ex) {
            throw new SSLPinningException("Failed to convert private key, error: " + ex.getMessage(), ex);
        }
    }

    /**
     * Prints public key in PEM format.
     * @param publicKey Public key.
     */
    private void printPublicKey(PublicKey publicKey) throws CryptoProviderException {
        final KeyConvertor keyConversionUtilities = new KeyConvertor();
        final byte[] publicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(publicKey);
        final String publicKeyEncoded = BaseEncoding.base64().encode(publicKeyBytes);
        System.out.println(publicKeyEncoded);
    }

    /**
     * Prints private key in PEM format.
     * @param privateKey Private key.
     */
    private void printPrivateKey(PrivateKey privateKey) {
        final KeyConvertor keyConversionUtilities = new KeyConvertor();
        final byte[] privateKeyBytes = keyConversionUtilities.convertPrivateKeyToBytes(privateKey);
        final String privateKeyEncoded = BaseEncoding.base64().encode(privateKeyBytes);
        System.out.println(privateKeyEncoded);
    }

}

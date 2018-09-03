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
import com.wultra.security.ssl.pinning.errorhandling.FingerprintSignatureException;
import com.wultra.security.ssl.pinning.model.FingerPrint;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SSL pinning tool command line application for generating signatures of SSL certificates.
 */
public class Application {

    private static final ASN1ObjectIdentifier PASSWORD_ENCRYPTION_ALGORITHM = PKCS8Generator.AES_128_CBC;

    /**
     * Main entry point.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) {

        initializeBC();

        CommandLine cmd = prepareCommandLine(args);
        if (cmd == null) {
            return;
        }

        executeCommand(cmd);
    }

    /**
     * Execute command based on command line options.
     *
     * @param cmd CommandLine instance.
     */
    private static void executeCommand(CommandLine cmd) {
        // Read configuration
        final String keyPairPath = cmd.getOptionValue("k");
        final String outputPath = cmd.getOptionValue("o");
        final String commonName = cmd.getOptionValue("n");
        final String fingerprint = cmd.getOptionValue("f");
        final String expires = cmd.getOptionValue("t");
        final String privateKeyPassword = cmd.getOptionValue("p");

        Long expirationTime = null;

        if (expires != null) {
            try {
                expirationTime = Long.parseLong(expires);
            } catch (NumberFormatException ex) {
                Logger.getLogger(Application.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                return;
            }
        }

        final String command = cmd.getArgList().get(0);

        switch (command) {
            case "sign":
                // Sign fingerprint data
                try {
                    if (keyPairPath == null) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Key pair path is not specified, cannot compute signature.");
                        return;
                    }
                    if (fingerprint == null) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Fingerprint is not specified, cannot compute signature.");
                        return;
                    }
                    if (expirationTime == null) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Expiration time is not specified, cannot compute signature.");
                        return;
                    }
                    if (outputPath == null) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Output path is not specified, cannot generate JSON file.");
                        return;
                    }
                    FingerPrint fingerPrint = sign(keyPairPath, privateKeyPassword, commonName, fingerprint, expirationTime);
                    generateJsonFile(outputPath, fingerPrint);
                } catch (Exception ex) {
                    Logger.getLogger(Application.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                }
                break;

            case "keygen":
                // Generate keypair
                try {
                    if (outputPath == null) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Output path is not specified, cannot generate key pair.");
                        return;
                    }
                    generateKeyPair(outputPath, privateKeyPassword);
                } catch (Exception ex) {
                    Logger.getLogger(Application.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                }
                break;

            default:
                // Unknown action
                Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Unknown command: " + command);
        }
    }

    /**
     * Initialize Bouncy Castle library.
     */
    private static void initializeBC() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
    }

    /**
     * Prepare command line object.
     * @param args Command line arguments.
     * @return Command line object.
     */
    private static CommandLine prepareCommandLine(String[] args) {
        // Parse options
        final Options options = buildOptions();

        // Prepare command line
        final CommandLine cmd;
        try {
            CommandLineParser parser = new DefaultParser();
            cmd = parser.parse(options, args);
            // Print options when user specified no options or help was invoked
            if (args.length == 0 || cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(100);
                formatter.printHelp("java -jar ssl-pinning-tool.jar", options);
                return null;
            }
        } catch (ParseException ex) {
            Logger.getLogger(Application.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return null;
        }
        return cmd;
    }

    /**
     * Build command line options.
     * @return Command line options.
     */
    private static Options buildOptions() {
        // Options definition
        final Options options = new Options();
        options.addOption("h", "help", false, "Print this help manual.");
        options.addOption("k", "keys", true, "EC key pair in PEM format stored as PKCS #8.");
        options.addOption("p", "password", true, "Password for encrypted key pair file.");
        options.addOption("o", "output", true, "Output file.");
        options.addOption("n", "name", true, "Domain common name.");
        options.addOption("f", "fingerprint", true, "SHA-256 fingerprint of certificate in HEX format.");
        options.addOption("t", "expires", true, "Expiration time in Unix timestamp format.");
        options.addOption("g", "generate", true, "Generate EC key pair.");
        return options;
    }

    /**
     * Sign fingerprint using private key.
     * @param privateKeyPath Path to private key file.
     * @param privateKeyPassword Private key password.
     * @param commonName Domain common name.
     * @param fingerprint SSL certificate SHA-256 fingerprint in HEX format.
     * @param expirationTime Expiration time as Unix timestamp.
     * @return FingerPrint object.
     * @throws FingerprintSignatureException Thrown when encryption fails.
     * @throws SignatureException Thrown when signature computation fails.
     * @throws InvalidKeyException Thrown when signature key is invalid.
     */
    private static FingerPrint sign(String privateKeyPath, String privateKeyPassword, String commonName, String fingerprint, long expirationTime)
            throws FingerprintSignatureException, SignatureException, InvalidKeyException {
        // Load private key
        final PrivateKey privKey = loadPrivateKey(privateKeyPath, privateKeyPassword);

        // Remove all whitespaces from fingerprint
        fingerprint = fingerprint.replaceAll("\\s+", "");

        // Convert fingerprint to byte[]
        byte[] fingerPrintBytes = Hex.decode(fingerprint);

        // Convert fingerprint bytes to Base64
        final String fingerprintBase64 = BaseEncoding.base64().encode(fingerPrintBytes);

        // Signature payload
        final String data = commonName + "&" + fingerprintBase64 + "&" + expirationTime;

        // Compute signature of payload using ECDSA with given EC private key
        final SignatureUtils utils = new SignatureUtils();
        byte[] signature = utils.computeECDSASignature(data.getBytes(Charsets.UTF_8), privKey);
        final String signatureBase64 = BaseEncoding.base64().encode(signature);

        // Return FingerPrint object
        return new FingerPrint(commonName, fingerprintBase64, expirationTime, signatureBase64);
    }

    /**
     * Load private key from file.
     * @param privateKeyPath Path to file with private key in PEM format.
     * @param password Private key password (optional).
     * @return Private key.
     */
    private static PrivateKey loadPrivateKey(String privateKeyPath, String password) throws FingerprintSignatureException {
        try (FileReader fileReader = new FileReader(privateKeyPath)) {
            final PEMParser pemParser = new PEMParser(new BufferedReader(fileReader));
            // Expected key type is EC
            final KeyFactory kf = KeyFactory.getInstance("EC");
            final Object pemInfo = pemParser.readObject();
            pemParser.close();
            if (pemInfo instanceof PrivateKeyInfo) {
                // Private key is not encrypted
                if (password != null) {
                    throw new FingerprintSignatureException("Private key is not encrypted, however private key password is specified.");
                }
                byte[] privateKeyBytes = ((PrivateKeyInfo) pemInfo).getEncoded();
                KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                return kf.generatePrivate(keySpec);
            } else if (pemInfo instanceof PKCS8EncryptedPrivateKeyInfo) {
                // Private key is encrypted by password, decrypt it
                PKCS8EncryptedPrivateKeyInfo pemPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemInfo;
                if (password == null) {
                    throw new FingerprintSignatureException("Private key is encrypted, however private key password is missing.");
                }
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(pemPrivateKeyInfo.decryptPrivateKeyInfo(provider));
            }
        } catch (Exception ex) {
            // Failed to create encryptor, PEM file will not be encrypted
            throw new FingerprintSignatureException("Failed to load private key, error: "+ex.getMessage(), ex);

        }
        throw new FingerprintSignatureException("Private key could not be loaded because of unknown format.");
    }

    /**
     * Generate EC key pair as PEM file.
     * @param outputPath Path to generated PEM file.
     * @param keyPairPassword Private key password (optional).
     * @throws IOException Thrown when key pair could not be generates.
     */
    private static void generateKeyPair(String outputPath, String keyPairPassword) throws IOException {
        final KeyGenerator keyGen = new KeyGenerator();
        final KeyPair keyPair = keyGen.generateKeyPair();
        OutputEncryptor encryptor = null;
        // The getEncoded() method returns key in PKCS8 format, it can be either unencrypted or encrypted
        if (keyPairPassword != null) {
            // Password was specified, generate encrypted PEM file
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PASSWORD_ENCRYPTION_ALGORITHM);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPasssword(keyPairPassword.toCharArray());
            try {
                encryptor = encryptorBuilder.build();
            } catch (OperatorCreationException ex) {
                // Failed to create encryptor, PEM file will not be encrypted
                Logger.getLogger(Application.class.getName()).log(Level.SEVERE, "Failed to create encryptor, PEM file will not be encrypted. Error: "+ex.getMessage(), ex);
            }
        }

        final PemObjectGenerator generator = new JcaPKCS8Generator(keyPair.getPrivate(), encryptor);

        // Generate PemObject using generator
        final PemObject pemObject = generator.generate();

        // Generate PEM file
        final FileWriter fw = new FileWriter(outputPath);
        try (PemWriter pemWriterPriv = new PemWriter(fw)) {
            pemWriterPriv.writeObject(pemObject);
            Logger.getLogger(Application.class.getName()).log(Level.INFO, "EC key pair generated in file: " + outputPath);
        }
    }

    /**
     * Generate JSON file.
     *
     * @param outputPath  Output path.
     * @param fingerPrint Fingerprint with signature details.
     * @throws IOException Thrown when JSON file could not be generated.
     */
    private static void generateJsonFile(String outputPath, FingerPrint fingerPrint) throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final FileWriter fw = new FileWriter(outputPath);
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.writeValue(fw, fingerPrint);
        fw.close();
        Logger.getLogger(Application.class.getName()).log(Level.INFO, "JSON output generated in file: " + outputPath);
    }


}

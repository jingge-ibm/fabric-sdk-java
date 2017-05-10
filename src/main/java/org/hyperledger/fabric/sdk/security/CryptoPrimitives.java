/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.security;

import java.lang.reflect.Method;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;
import java.util.Properties;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.SDKUtil;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoPrimitives implements CryptoSuite {
    private final Config config = Config.getConfig();

    private String curveName;
    private CertificateFactory cf;
    private String hashAlgorithm = config.getHashAlgorithm();
    private int securityLevel = config.getSecurityLevel();
    private String CERTIFICATE_FORMAT = config.getCertificateFormat();
    private String DEFAULT_SIGNATURE_ALGORITHM = config.getSignatureAlgorithm();

    // Following configuration settings are hardcoded as they don't deal with any interactions with Fabric MSP and BCCSP components
    // If you wish to make these customizable, follow the logic from setProperties();
    private String ASYMMETRIC_KEY_TYPE = "EC";
    private String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private String SYMMETRIC_KEY_TYPE = "AES";
    private int SYMMETRIC_KEY_BYTE_COUNT = 32;
    private String SYMMETRIC_ALGORITHM = "AES/CFB/NoPadding";
    private int MAC_KEY_BYTE_COUNT = 32;

    private static final Log logger = LogFactory.getLog(CryptoPrimitives.class);

    /**
     * sets the signature algorithm used for signing/verifying.
     *
     * @param sigAlg the name of the signature algorithm. See the list of valid names in the JCA Standard Algorithm Name documentation
     */
    public void setSignatureAlgorithm(String sigAlg) {
        this.DEFAULT_SIGNATURE_ALGORITHM = sigAlg ;
    }

    /**
     * returns the signature algorithm used by this instance of CryptoPrimitives.
     * Note that fabric and fabric-ca have not yet standardized on which algorithms are supported.
     * While that plays out, CryptoPrimitives will try the algorithm specified in the certificate and
     * the default SHA256withECDSA that's currently hardcoded for fabric and fabric-ca
     *
     * @return the name of the signature algorithm
     */
    public String getSignatureAlgorithm() {
        return this.DEFAULT_SIGNATURE_ALGORITHM;
    }

    public Certificate bytesToCertificate(byte[] certBytes) throws CryptoException {
        if (certBytes == null || certBytes.length == 0) {
            throw new CryptoException("bytesToCertificate: input null or zero length");
        }

        X509Certificate certificate;
        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certBytes));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            certificate = (X509Certificate) certFactory.generateCertificate(pem);
        } catch (CertificateException e) {
            String emsg = "Unable to converts byte array to certificate. error : " + e.getMessage();
            logger.error(emsg);
            logger.debug("input bytes array :" + new String(certBytes));
            throw new CryptoException(emsg, e);
        }

        return certificate;
    }

    /**
     * Verify a signature.
     *
     * @param plainText original text.
     * @param signature signature value as a byte array.
     * @param pemCertificate the X509 certificate to be used for verification
     * @return
     * @throws CryptoException
     */
    @Override
    public boolean verify(byte[] plainText, byte[] signature, byte[] pemCertificate) throws CryptoException {
        boolean isVerified = false;

        if (plainText == null || signature == null || pemCertificate == null) {
            return false;
        }

        logger.trace("plaintext in hex: " + DatatypeConverter.printHexBinary(plainText));
        logger.trace("signature in hex: " + DatatypeConverter.printHexBinary(signature));
        logger.trace("PEM cert in hex: " + DatatypeConverter.printHexBinary(pemCertificate));

        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(pemCertificate));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
            isVerified = validateCertificate(certificate);
            if (isVerified) { // only proceed if cert is trusted
                String signatureAlgorithm = certificate.getSigAlgName() ;
                Signature sig = Signature.getInstance(signatureAlgorithm);
                sig.initVerify(certificate);
                sig.update(plainText);
                isVerified = sig.verify(signature);
                if (! isVerified) {
                    // TODO currently fabric is trying to decide if the signature algorithm should
                    // be passed along inside the certificate or configured manually or included in
                    // the message itself. fabric-ca is also about to align its defaults with fabric.
                    // while we wait, we will try both the algorithm specified in the cert and the
                    // hardcoded default from fabric/fabric-ca
                    sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
                    sig.initVerify(certificate);
                    sig.update(plainText);
                    isVerified = sig.verify(signature);
                }
            }
        } catch (InvalidKeyException | CertificateException e) {
            CryptoException ex = new CryptoException("Cannot verify signature. Error is: "
                            + e.getMessage() + "\r\nCertificate: "
                            + DatatypeConverter.printHexBinary(pemCertificate),e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        } catch (NoSuchAlgorithmException | SignatureException e) {
            CryptoException ex = new CryptoException("Cannot verify. Signature algorithm is invalid. Error is: " + e.getMessage(),e);
            logger.error(ex.getMessage(), ex) ;
            throw ex;
        }

        return isVerified;
    } // verify

    private KeyStore trustStore = null;

    private void createTrustStore() throws CryptoException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            setTrustStore(keyStore);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | InvalidArgumentException e) {
            throw new CryptoException("Cannot create trust store. Error: " + e.getMessage(), e);
        }
    }

    /**
     * setTrustStore uses the given KeyStore object as the container for trusted
     * certificates
     *
     * @param keyStore
     *            the KeyStore which will be used to hold trusted certificates
     * @throws InvalidArgumentException
     */
    public void setTrustStore(KeyStore keyStore) throws InvalidArgumentException {

        if (keyStore == null) {
            throw new InvalidArgumentException("Need to specify a java.security.KeyStore input parameter");
        }

        trustStore = keyStore;
    }

    /**
     * getTrustStore returns the KeyStore object where we keep trusted certificates.
     * If no trust store has been set, this method will create one.
     *
     * @return the trust store as a java.security.KeyStore object
     * @throws CryptoException
     * @see KeyStore
     */
    public KeyStore getTrustStore() throws CryptoException {
        if (trustStore == null) {
            createTrustStore();
        }
        return trustStore;
    }

    /**
     * addCACertificateToTrustStore adds a CA cert to the set of certificates used for signature validation
     * @param caCertPem an X.509 certificate in PEM format
     * @param alias an alias associated with the certificate. Used as shorthand for the certificate during crypto operations
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void addCACertificateToTrustStore(File caCertPem, String alias) throws CryptoException, InvalidArgumentException {

        if (alias==null || alias.isEmpty()) {
            throw new InvalidArgumentException("You must assign an alias to a certificate when adding to the trust store.");
        }

        BufferedInputStream bis;
        try {

            bis = new BufferedInputStream(new ByteArrayInputStream(FileUtils.readFileToByteArray(caCertPem)));
            Certificate caCert = cf.generateCertificate(bis) ;
            this.addCACertificateToTrustStore(caCert, alias);
        } catch (CertificateException | IOException e) {
            throw new CryptoException("Unable to add CA certificate to trust store. Error: " + e.getMessage(), e);
        }
    }

    /**
     * addCACertificateToTrustStore adds a CA cert to the set of certificates used for signature validation
     * @param caCert an X.509 certificate
     * @param alias an alias associated with the certificate. Used as shorthand for the certificate during crypto operations
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void addCACertificateToTrustStore(Certificate caCert, String alias) throws InvalidArgumentException, CryptoException {

        if (alias==null || alias.isEmpty()) {
            throw new InvalidArgumentException("You must assign an alias to a certificate when adding to the trust store.");
        }
        if (caCert == null) {
            throw new InvalidArgumentException("Certificate cannot be null.");
        }

        try {
            logger.trace("Adding cert to trust store. alias:  " + alias + "cert: " + caCert.toString());
            getTrustStore().setCertificateEntry(alias, caCert);
        } catch (KeyStoreException e) {
            String emsg = "Unable to add CA certificate to trust store. Error: "+ e.getMessage();
            logger.error(emsg, e);
            throw new CryptoException(emsg, e);
        }
    }

    @Override
    public void loadCACertificates(Collection<Certificate> CACertificates) throws CryptoException {
        if (CACertificates == null || CACertificates.size() == 0) {
            throw new CryptoException("Unable to load CA certificates. List is empty");
        }

        try {
            for (Certificate cert : CACertificates) {
                addCACertificateToTrustStore(cert, Integer.toString(cert.hashCode()));
            }
        } catch (InvalidArgumentException e) {
            String emsg = "Unable to add certificate to trust store. Error: " + e.getMessage();
            logger.error(emsg, e);
            throw new CryptoException(emsg, e);
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#loadCACertificatesAsBytes(java.util.Collection)
     */
    @Override
    public void loadCACertificatesAsBytes(Collection<byte[]> CACertificatesBytes) throws CryptoException {
        if (CACertificatesBytes == null || CACertificatesBytes.size() == 0) {
            throw new CryptoException("List of CA certificates is empty. Nothing to load.");
        }
        ArrayList<Certificate> certList = new ArrayList<>();
        for (byte[] certBytes : CACertificatesBytes) {
            logger.trace("certificate to load:\n" + new String(certBytes));
            certList.add(bytesToCertificate(certBytes));
        }
        loadCACertificates(certList);
    }

    /**
     * loadCACerts loads into the trust stores all the certificates it finds in the <i>cacert</i> directory.
     * This method assumes that any file with extension <i>.pem</i> is a certificate file
     */
    private void loadCACerts() {
        File certsFolder = new File("cacerts").getAbsoluteFile();
        Collection<File> certFiles = FileUtils.listFiles(certsFolder, new String[]{"pem"}, false);
        for (File certFile : certFiles) {
            try {
                addCACertificateToTrustStore(certFile, certFile.getName());
                logger.debug("adding " + certFile.getName() + "to truststore.");
            } catch (CryptoException | InvalidArgumentException e) {
                logger.error("Unable to load certificate " + certFile.getName() + "Error: " + e.getMessage(), e);
                // ignore cert files we can't read
            }
        }
    }

    /**
     * validateCertificate checks whether the given certificate is trusted. It
     * checks if the certificate is signed by one of the trusted certs in the
     * trust store.
     *
     * @param certPEM
     *            the certificate in PEM format
     * @return true if the certificate is trusted
     */
    public boolean validateCertificate(byte[] certPEM) {

        if (certPEM == null) {
            return false;
        }

        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certPEM));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
            return validateCertificate(certificate);
        } catch (CertificateException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage() + "\r\nCertificate (PEM, hex): "
                            + DatatypeConverter.printHexBinary(certPEM));
            return false;
        }
    }

    public boolean validateCertificate(Certificate cert) {
        boolean isValidated = false;

        if (cert == null) {
            return isValidated;
        }

        try {
            KeyStore keyStore = getTrustStore();
            if (keyStore == null) {
                throw new CryptoException("Crypto does not have a trust store. No certificate can be validated", null);
            }

            PKIXParameters parms = new PKIXParameters(keyStore);
            parms.setRevocationEnabled(false);

            CertPathValidator certValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType()); // PKIX

            ArrayList<Certificate> start = new ArrayList<Certificate>();
            start.add(cert);
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            CertPath certPath = certFactory.generateCertPath(start);

            certValidator.validate(certPath, parms);
            isValidated = true;
        } catch (KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                        | CertificateException | CertPathValidatorException | CryptoException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage() + "\r\nCertificate"
                            + cert.toString());
            isValidated = false;
        }

        return isValidated;
    } // validateCertificate

    public int getSecurityLevel() {
        return securityLevel;
    }

    /**
     * Security Level determines the elliptic curve used in key generation
     * @param securityLevel  currently 256 or 384
     * @throws InvalidArgumentException
     */
    public void setSecurityLevel(int securityLevel) throws InvalidArgumentException {
        if (securityLevel != 256 && securityLevel != 384) {
            throw new InvalidArgumentException("Illegal level: " + securityLevel + " must be either 256 or 384");
        }


        // TODO need to get set of supported curves from #fabric-crypto team
        if (this.securityLevel == 256) {
            this.curveName = "P-256";
        } else if (this.securityLevel == 384) {
            this.curveName = "secp384r1";
        }
    }

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public void setHashAlgorithm(String algorithm) throws InvalidArgumentException {
        if (SDKUtil.isNullOrEmpty(algorithm)
                        || !(algorithm.equalsIgnoreCase("SHA2") || algorithm.equalsIgnoreCase("SHA3"))) {
            throw new InvalidArgumentException("Illegal Hash function family: "
                        + this.hashAlgorithm + " - must be either SHA2 or SHA3");
        }

        this.hashAlgorithm = algorithm;
    }

    @Override
    public KeyPair keyGen() throws CryptoException {
        return ecdsaKeyGen();
    }

    private KeyPair ecdsaKeyGen() throws CryptoException {
        return generateKey("ECDSA", this.curveName);
    }

    private KeyPair generateKey(String encryptionName, String curveName) throws CryptoException {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = KeyPairGenerator.getInstance(encryptionName);
            g.initialize(ecGenSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            return pair;
        } catch (Exception exp) {
            throw new CryptoException("Unable to generate key pair", exp);
        }
    }

    public String encodePublicKey(PublicKey pk) {
        return DatatypeConverter.printHexBinary(pk.getEncoded());
    }

    public PublicKey decodePublicKey(String data) throws CryptoException {
        try {
            logger.debug("input encoded public key: " + data);
            KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE);
            X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(data));
            return asymmetricKeyFactory.generatePublic(pubX509);
        }
        catch (Exception e) {
            String emsg = "Failed to decode public key: " + data + ". error : " + e.getMessage();
            logger.error(emsg);
            throw new CryptoException(emsg, e);
        }
    }

    private BigInteger[] parseRAndSFromSignature(byte[] signature) {
        /* Signature format:
         * 0x03, <Sequence of length>, 0x02, <R length>, <R>, <0x02>, <S length>, <S>
         */

        BigInteger r = null;
        BigInteger s = null;

        int rLength = signature[3];
        int rStartIndex = 4;
        int sLength = signature[5+rLength];
        int sStartIndex = 4+rLength+2;

        byte[] rByte = new byte[rLength];
        byte[] sByte = new byte[sLength];

        System.arraycopy(signature, rStartIndex, rByte, 0, rLength);
        System.arraycopy(signature, sStartIndex, sByte, 0 ,sLength);

        r = new BigInteger(rByte);
        s = new BigInteger(sByte);

        return new BigInteger[] {r, s};
    }

    private byte[] createSignatureFromRAndS(BigInteger[] signature) {
        byte[] rByte = signature[0].toByteArray();
        byte[] sByte = signature[1].toByteArray();

        byte[] sig = new byte[rByte.length + sByte.length + 6];

        sig[0] = 0x03;
        sig[1] = (byte)(sig.length - 2);
        sig[2] = 0x02;
        sig[3] = (byte)(rByte.length);
        System.arraycopy(rByte, 0, sig, 4, rByte.length);
        sig[rByte.length+4] = 0x02;
        sig[rByte.length+5] = (byte)(sByte.length);
        System.arraycopy(sByte, 0, sig, rByte.length+6, sByte.length);

        return sig;
    }

    /**
     * ecdsaSignToBytes - sign to bytes
     *
     * @param privateKey private key.
     * @param data data to sign
     * @return
     * @throws CryptoException
     */

    public byte[] ecdsaSignToBytes(PrivateKey key, byte[] data) throws CryptoException {
        try {
            if (key == null || data == null)
                throw new CryptoException("Could not sign. Key or plain text is null", new NullPointerException());

            byte[] signature;
            Signature sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
            sig.initSign(key);
            sig.update(data);
            signature = sig.sign();

            // Get the order of the curve
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(this.curveName));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

            BigInteger[] signBigInts = preventMalleability(parseRAndSFromSignature(signature), ecParameters.getOrder());

            return createSignatureFromRAndS(signBigInts);
        } catch (Exception e) {
            throw new CryptoException("Could not sign the message using private key", e);
        }
    }

    @Override
    public byte[] sign(PrivateKey key, byte[] data) throws CryptoException {
        return ecdsaSignToBytes(key, data);
    }

    private BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curve_n) {
        BigInteger cmpVal = curve_n.divide(BigInteger.valueOf(2l));

        BigInteger sval = sigs[1];

        if (sval.compareTo(cmpVal) == 1) {

            sigs[1] = curve_n.subtract(sval);
        }

        return sigs;
    }

    /**
     * generateCertificationRequest
     *
     * @param subject The subject to be added to the certificate
     * @param pair Public private key pair
     * @return An certificate signing request in PEM format
     * @throws CryptoException
     */

    public String generateCertificationRequest(String subject, KeyPair pair)
                    throws CryptoException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);
        Signature sig = null;
        try {
            sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(pair.getPrivate());
        } catch (Exception e) {
            throw new CryptoException("Cannot create csr");
        }


        try {
            Class pkcs10 = null;
            try {
                pkcs10 = Class.forName("sun.security.pkcs10.PKCS10");
            } catch (ClassNotFoundException e) {
                pkcs10 = Class.forName("sun.security.pkcs.PKCS10");
            }
            
            Class x500name = Class.forName("sun.security.x509.X500Name");

            Object x500nameObj = x500name.getConstructor(String.class).newInstance("CN=" + subject);
            Object pkcs10Obj = pkcs10.getConstructor(PublicKey.class).newInstance(pair.getPublic());

            Method encodeAndSign = pkcs10.getMethod("encodeAndSign", x500name, Signature.class);
            Method print = pkcs10.getMethod("print", PrintStream.class);

            encodeAndSign.invoke(pkcs10Obj, x500nameObj, sig);
            print.invoke(pkcs10Obj, printStream);

        } catch (Exception e) {
            // Try IBM package
            try {
                Class pkEeCertReqTransaction = Class.forName("com.ibm.security.certclient.PkEeCertReqTransaction");
                Class pkEeCertReqFactory     = Class.forName("com.ibm.security.certclient.PkEeCertReqFactory");

                Method newCertRequest = pkEeCertReqFactory.getMethod("newCertRequest", 
                    int.class, 
                    String.class, 
                    int.class, 
                    String.class,
                    String.class,
                    boolean.class,
                    List.class,
                    List.class,
                    List.class,
                    String.class,
                    String.class,
                    String.class,
                    KeyPair.class);
                Method getPKCS10CertReq = pkEeCertReqTransaction.getMethod("getPKCS10CertReq", null);

                Object pkEeCertReqTransactionObj = newCertRequest.invoke(pkEeCertReqFactory, 
                    this.securityLevel,
                    "CN=" + subject,
                    365,
                    "EC",
                    "SHA256withECDSA",
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    pair);
                byte[] encoded = (byte[]) getPKCS10CertReq.invoke(pkEeCertReqTransactionObj, null);
                printStream.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
                printStream.println(Base64.getMimeEncoder().encodeToString(encoded));
                printStream.println("-----END NEW CERTIFICATE REQUEST-----");
                outStream.close();
            } catch (Exception ex) {
                throw new CryptoException("Cannot create csr");
            } 
        }

        return outStream.toString();
    }

    public PrivateKey ecdsaKeyFromPrivate(byte[] key) throws CryptoException {
        try {
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory generator = KeyFactory.getInstance("ECDSA");
            PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

            return privateKey;
        } catch (Exception exp) {
            throw new CryptoException("Unable to convert byte[] into PrivateKey", exp);
        }
    }

    @Override
    public byte[] hash(byte[] input) {
        MessageDigest digest = getHashDigest();
        return digest.digest(input);
    }

    @Override
    public void init() throws CryptoException, InvalidArgumentException {
        resetConfiguration();
    }

    private MessageDigest getHashDigest() {
        if (this.hashAlgorithm.equalsIgnoreCase("SHA3")) {
            throw new IllegalArgumentException("SHA3 is not supported currently");
        } else {
            MessageDigest m = null;
            try {
                m = MessageDigest.getInstance("SHA-256");
            } catch (Exception e) {
                // Should not happen
                throw new IllegalArgumentException("Unable to get SHA-256");
            }
            return m;
        }
    }

    /**
     * Resets curve name, hash algorithm and cert factory. Call this method when a config value changes
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    private void resetConfiguration() throws CryptoException, InvalidArgumentException {

        this.setSecurityLevel(this.securityLevel);

        this.setHashAlgorithm(this.hashAlgorithm);

        try {
            cf = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
        } catch (CertificateException e) {
            CryptoException ex = new CryptoException("Cannot initialize " + CERTIFICATE_FORMAT + " certificate factory. Error = " + e.getMessage(), e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#setProperties(java.util.Properties)
     */
    @Override
    public void setProperties(Properties properties) throws CryptoException, InvalidArgumentException {
        if (properties != null) {
        hashAlgorithm = Optional.ofNullable(properties.getProperty(Config.HASH_ALGORITHM)).orElse(hashAlgorithm);
        String secLevel = Optional.ofNullable(properties.getProperty(Config.SECURITY_LEVEL)).orElse(Integer.toString(securityLevel));
        securityLevel = Integer.parseInt(secLevel);
        CERTIFICATE_FORMAT = Optional.ofNullable(properties.getProperty(Config.CERTIFICATE_FORMAT)).orElse(CERTIFICATE_FORMAT);
        DEFAULT_SIGNATURE_ALGORITHM = Optional.ofNullable(properties.getProperty(Config.SIGNATURE_ALGORITHM)).orElse(DEFAULT_SIGNATURE_ALGORITHM);

        resetConfiguration() ;
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#getProperties()
     */
    @Override
    public Properties getProperties() {
        Properties properties = new Properties();
        properties.setProperty(Config.HASH_ALGORITHM, hashAlgorithm);
        properties.setProperty(Config.SECURITY_LEVEL, Integer.toString(securityLevel));
        properties.setProperty(Config.CERTIFICATE_FORMAT, CERTIFICATE_FORMAT);
        properties.setProperty(Config.SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_ALGORITHM);
        return properties ;
    }

    public byte[] certificateToDER(String certricatePEM){

        String[] parts = certricatePEM.split("\n");

        if (parts.length != 3) return null;

        return Base64.getMimeDecoder().decode(parts[1]);
    }
}

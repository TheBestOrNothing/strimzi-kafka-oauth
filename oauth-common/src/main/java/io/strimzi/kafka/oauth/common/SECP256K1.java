/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class with methods for introspecting a JWT token
 */
public class SECP256K1 {

    private String algorithm;
    private String mode;
    private String curveName;
    private ECKey aliceJWK;
    private ECKey bobJWK;
    //private IvParameterSpec iv;

    /**
     * Create a new instance
     */
    public SECP256K1() {
        try {
            this.aliceJWK = new ECKeyGenerator(Curve.SECP256K1).generate();
            this.bobJWK = new ECKeyGenerator(Curve.SECP256K1).generate();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        this.algorithm = "AES";
        this.mode = "CBC";
        //this.iv = generateIV();
        this.curveName = "secp256k1";
    }

    public String message2Token(String message) {
        String token = null;
        // Generate EC key pair on the secp256k1 curve
        try {
            Date newExpirationTime = new Date(System.currentTimeMillis() + 3600 * 1000); // 1 hour from now
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            builder.expirationTime(newExpirationTime);
            builder.claim("aliceJWK", aliceJWK.toPublicJWK().toString());
            builder.claim("bobJWK", bobJWK.toJSONString());
            //builder.claim("message", message);
            builder.claim("algorithm", algorithm);
            builder.claim("mode", mode);
            IvParameterSpec iv = generateIV();
            builder.claim("iv", Base64.getEncoder().encodeToString(iv.getIV()));
            String encryptedMessage = encryptedMessage(message, algorithm, mode, iv, aliceJWK, bobJWK);
            builder.claim("encryptedMessage", encryptedMessage);
            //byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
            //String decryptedMessageBase64 = decryptedMessage(encryptedMessageBytes, algorithm, mode, iv, bobJWK, aliceJWK);
            //builder.claim("decryptedMessage", new String(Base64.getDecoder().decode(decryptedMessageBase64)));
            JWTClaimsSet claimsSet = builder.build();
            
            // Create JWT for ES256K alg
            SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256K)
                    .keyID(aliceJWK.toJSONString())
                    .type(null)
                    .build(),
                    claimsSet);

            // Sign with private EC key
            jwt.sign(new ECDSASigner(aliceJWK));

            // Output the JWT
            token = jwt.serialize();
            //System.out.println(token);

            // Verify the ES256K signature with the public EC key
            if (jwt.verify(new ECDSAVerifier(aliceJWK))) {
                System.out.println("message2Token ... ... ... ... ... ... ... ...");
                System.out.println(jwt.getJWTClaimsSet().toJSONObject());
            }
        } catch (Exception e) {
            System.out.println("Exception Occure when message2Token");
        }

        return token;
    }

    public String token2Message(String token) {
        String message = null;
        // Generate EC key pair on the secp256k1 curve
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            String ecPublicKeyStr = jwt.getHeader().getKeyID();
            ECKey ecPublicJWK = ECKey.parse(ecPublicKeyStr);
            
            if (jwt.verify(new ECDSAVerifier(ecPublicJWK))) {
                JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
                System.out.println("token2Message ... ... ... ... ... ... ... ...");
                System.out.println(claimsSet.toJSONObject());
                ECKey aliceJWK = ECKey.parse(claimsSet.getClaim("aliceJWK").toString());
                ECKey bobJWK = ECKey.parse(claimsSet.getClaim("bobJWK").toString());
                String algorithm = claimsSet.getClaim("algorithm").toString();
                String mode = claimsSet.getClaim("mode").toString();
                String ivStr = claimsSet.getClaim("iv").toString();
                byte[] ivBytes = Base64.getDecoder().decode(ivStr);
                IvParameterSpec ivParam = new IvParameterSpec(ivBytes);

                String encryptedMessageBase64 = claimsSet.getClaim("encryptedMessage").toString();
                byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
                String decryptedMessageBase64 = decryptedMessage(encryptedMessage, algorithm, mode, ivParam, bobJWK, aliceJWK);
                message = new String(Base64.getDecoder().decode(decryptedMessageBase64));
                //System.out.printf("The message is: %s%n", message);
            } else {
                System.out.printf("Verify failed%n");
            }

        } catch (JOSEException | ParseException e) {
            System.out.println("Exception Occure");
        }

        return message;
    }
    private String encryptedMessage(String message, String algorithm, String mode, IvParameterSpec iv, ECKey aliceJWK, ECKey bobJWK) {
        ECCurve curve = ECNamedCurveTable.getParameterSpec(this.curveName).getCurve();
        ECDomainParameters domainParameters = new ECDomainParameters(CustomNamedCurves.getByName(this.curveName));
        //Convert private ECKey to ECPrivateKeyParameters
        BigInteger alicePrivateKeyInt = aliceJWK.getD().decodeToBigInteger();
        ECPrivateKeyParameters alicePrivateKey = new ECPrivateKeyParameters(alicePrivateKeyInt, domainParameters);
        //Convert public ECKey to ECPublicKeyParameters
        ECPoint bobPoint = curve.createPoint(bobJWK.getX().decodeToBigInteger(), bobJWK.getY().decodeToBigInteger());
        ECPublicKeyParameters bobPublicKey = new ECPublicKeyParameters(bobPoint, domainParameters);

        byte[] sharedSecretAlice = computeSharedSecret(alicePrivateKey, bobPublicKey);
        //System.out.printf("sharedSecretAlice in encryptedMessage is: %s%n", Base64.getEncoder().encodeToString(sharedSecretAlice));
        byte[] encryptedMsg = encrypt(message, algorithm, mode, iv, sharedSecretAlice);
        String encryptedMsgBase64 = Base64.getEncoder().encodeToString(encryptedMsg);
        return encryptedMsgBase64;
    }

    private String decryptedMessage(byte[] message, String algorithm, String mode, IvParameterSpec iv, ECKey aliceJWK, ECKey bobJWK) {
        ECCurve curve = ECNamedCurveTable.getParameterSpec(this.curveName).getCurve();
        ECDomainParameters domainParameters = new ECDomainParameters(CustomNamedCurves.getByName(this.curveName));
        //Convert private ECKey to ECPrivateKeyParameters
        BigInteger alicePrivateKeyInt = aliceJWK.getD().decodeToBigInteger();
        ECPrivateKeyParameters alicePrivateKey = new ECPrivateKeyParameters(alicePrivateKeyInt, domainParameters);
        //Convert public ECKey to ECPublicKeyParameters
        ECPoint bobPoint = curve.createPoint(bobJWK.getX().decodeToBigInteger(), bobJWK.getY().decodeToBigInteger());
        ECPublicKeyParameters bobPublicKey = new ECPublicKeyParameters(bobPoint, domainParameters);

        byte[] sharedSecretAlice = computeSharedSecret(alicePrivateKey, bobPublicKey);
        //System.out.printf("sharedSecretAlice in decryptedMessage is: %s%n", Base64.getEncoder().encodeToString(sharedSecretAlice));
        byte[] decryptedMsg = decrypt(message, algorithm, mode, iv, sharedSecretAlice);
        String decryptedMsgBase64 = Base64.getEncoder().encodeToString(decryptedMsg);
        return decryptedMsgBase64;
    }

    public void testECDH() {
        // Step 1: Generate shared secret key
        // Generate key pairs for Alice and Bob
        AsymmetricCipherKeyPair aliceKeyPair = generateKeyPair();
        AsymmetricCipherKeyPair bobKeyPair = generateKeyPair();
        // Extract Alice's private key and Bob's public key
        ECPrivateKeyParameters alicePrivateKey = (ECPrivateKeyParameters) aliceKeyPair.getPrivate();
        ECPrivateKeyParameters bobPrivateKey = (ECPrivateKeyParameters) bobKeyPair.getPrivate();
        ECPublicKeyParameters alicePublicKey = (ECPublicKeyParameters) aliceKeyPair.getPublic();
        ECPublicKeyParameters bobPublicKey = (ECPublicKeyParameters) bobKeyPair.getPublic();

        // Alice computes shared secret
        byte[] sharedSecretAlice = computeSharedSecret(alicePrivateKey, bobPublicKey);
        // Bob computes shared secret
        byte[] sharedSecretBob = computeSharedSecret(bobPrivateKey, alicePublicKey); 

        // Ensure the shared secrets match
        boolean secretsMatch = MessageDigest.isEqual(sharedSecretAlice, sharedSecretBob);

        if (secretsMatch) {
            System.out.println("Shared secrets match");
        } else {
            System.out.println("Shared secrets do not match");
            return;
        }
        
        try {
            // Encrypt message with shared secret
            // Step 2: Prepare the plaintext
            String message = "Hello";

            // Step 3: Choose encryption algorithm and mode
            String algorithm = "AES";
            String mode = "CBC";

            // Step 4: Generate Initialization Vector (IV)
            IvParameterSpec iv = generateIV();

            // Step 5: Encrypt the data 
            byte[] encryptedMessageBytes = encrypt(message, algorithm, mode, iv, sharedSecretAlice);
            String encryptedMessage = encryptedMessage(message, algorithm, mode, iv, aliceJWK, bobJWK);
            System.out.println("Encrypted message 1: " + Base64.getEncoder().encodeToString(encryptedMessageBytes));
            System.out.println("Encrypted message 2: " + encryptedMessage);
            // Step 6: Transmit ciphertext, IV, algorithm, and mode to Bob 

            // Step 7：Decrypt message with shared secret
            byte[] decryptedMessageBytes = decrypt(encryptedMessageBytes, algorithm, mode, iv, sharedSecretBob);
            // Convert the received string back to a byte array
            //byte[] decodedByteArray = Base64.getDecoder().decode(receivedString);
            // Convert byte array back to a string
            String decryptedMessageStr = new String(decryptedMessageBytes);
            System.out.println("Decrypted message 1: " + decryptedMessageStr);
            String decryptedMessage = decryptedMessage(Base64.getDecoder().decode(encryptedMessage), algorithm, mode, iv, bobJWK, aliceJWK);
            System.out.println("Decrypted message 2: " + new String(Base64.getDecoder().decode(decryptedMessage)));
        } catch (java.lang.Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private AsymmetricCipherKeyPair generateKeyPair() {
        ECDomainParameters domainParameters = new ECDomainParameters(CustomNamedCurves.getByName(this.curveName));
        // Generate key pair
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        generator.init(generationParameters);
        return generator.generateKeyPair();
    }

    private byte[] computeSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey) {
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privateKey);
        BigInteger sharedSecret = agreement.calculateAgreement(publicKey);
        //return sharedSecret.toByteArray();
        // To fix the length of sharedkey to 256bits
        HKDFBytesGenerator kdf = new HKDFBytesGenerator(new SHA256Digest());
        kdf.init(new HKDFParameters(sharedSecret.toByteArray(), null, null));
        byte[] derivedKey = new byte[32]; // 256-bit key length
        kdf.generateBytes(derivedKey, 0, derivedKey.length);
        return derivedKey;
    }

    // Generate a random IV
    private IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // 16 bytes for AES
        // Generate a random IV
        // Note: In a real scenario, use a secure random generator for IV generation
        //       For demonstration purposes, this uses a random fixed IV
        //       Never reuse the same IV with the same key
        //       IV should be securely transmitted or included with the ciphertext
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private byte[] encrypt(String message, String algorithm, String mode, IvParameterSpec iv, byte[] sharedSecret) {
        Cipher cipher;
        byte[] encryptMsg = null;
        try {
            cipher = Cipher.getInstance(algorithm + "/" + mode + "/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            encryptMsg = cipher.doFinal(message.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return encryptMsg;
    }

    private byte[] decrypt(byte[] encryptedMessage, String algorithm, String mode, IvParameterSpec iv, byte[] sharedSecret) {
        Cipher cipher;
        byte[] decryptedBytes = null;
        try {
            cipher = Cipher.getInstance(algorithm + "/" + mode + "/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            decryptedBytes = cipher.doFinal(encryptedMessage);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return decryptedBytes;
    }

}

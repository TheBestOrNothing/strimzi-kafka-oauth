/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;
import org.web3j.crypto.ECKeyPair;

/**
 * A class with methods for introspecting a JWT token
 */
public class WEB3 {
    public ECPrivateKey ecPrivateKey;
    public ECPoint point;
    public String address;

    public ECKey nimbusdsJWK;
    public ECKeyPair web3KeyPair;
    //prefix without '0x04' from uncompressed public key
    public BigInteger publicKey;
    /**
     * Create a new instance
     */
    public WEB3() {
        try {
            //this.jwk = new ECKeyGenerator(Curve.SECP256K1).generate();
            this.nimbusdsJWK = new ECKeyGenerator(Curve.SECP256K1).generate();
            KeyPair javaKeyPair = this.nimbusdsJWK.toKeyPair();
            this.ecPrivateKey = (ECPrivateKey) javaKeyPair.getPrivate();
            this.web3KeyPair = ECKeyPair.create(align2FieldSize(this.ecPrivateKey.getS())); 
            this.point = Sign.publicPointFromPrivate(align2FieldSize(this.web3KeyPair.getPrivateKey()));
            this.publicKey = this.web3KeyPair.getPublicKey();
            this.address = Keys.getAddress(align2FieldSize(this.publicKey));
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public WEB3(ECKey jwk) {
        try {
            this.nimbusdsJWK = jwk;
            KeyPair javaKeyPair = jwk.toKeyPair();
            this.ecPrivateKey = (ECPrivateKey) javaKeyPair.getPrivate();
            this.web3KeyPair = ECKeyPair.create(align2FieldSize(this.ecPrivateKey.getS())); 
            this.point = Sign.publicPointFromPrivate(align2FieldSize(this.web3KeyPair.getPrivateKey()));
            this.publicKey = this.web3KeyPair.getPublicKey();
            this.address = Keys.getAddress(align2FieldSize(this.publicKey));
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public WEB3(ECPrivateKey ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
        this.web3KeyPair = ECKeyPair.create(align2FieldSize(ecPrivateKey.getS())); 
        this.point = Sign.publicPointFromPrivate(align2FieldSize(this.web3KeyPair.getPrivateKey()));
        this.publicKey = this.web3KeyPair.getPublicKey();
        this.address = Keys.getAddress(align2FieldSize(this.publicKey));
        byte[] x = this.point.normalize().getXCoord().getEncoded();
        byte[] y = this.point.normalize().getYCoord().getEncoded();
        this.nimbusdsJWK = new ECKey.Builder(Curve.SECP256K1, Base64URL.encode(x), Base64URL.encode(y))
                .d(Base64URL.encode(align2FieldSize(ecPrivateKey.getS())))
                .build();
    }

    //There are many types of publickey in this, compressed, uncompressed, hybird
    //All these types can be decode by curve.decodePoint function
    //prefix without '0x04' from uncompressed public key
    public WEB3(BigInteger publicKey) {
        this.publicKey = publicKey;
        this.address = Keys.getAddress(this.publicKey);
        ECDomainParameters curv = new ECDomainParameters(CustomNamedCurves.getByName("secp256k1"));
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(publicKey, 1 + x9.getByteLength(curv.getCurve()) * 2);
        compEnc[0] = 0x04;
        this.point = curv.getCurve().decodePoint(compEnc);
        byte[] x = point.normalize().getXCoord().getEncoded();
        byte[] y = point.normalize().getYCoord().getEncoded();
        //this.address = Keys.getAddress(this.ecKeyPair.getPublicKey());
        this.nimbusdsJWK = new ECKey.Builder(Curve.SECP256K1, Base64URL.encode(x), Base64URL.encode(y)).build();
        this.ecPrivateKey = null;
        this.web3KeyPair = null;
    }

    public void printWeb3() {
        System.out.println();
        System.out.println(this.nimbusdsJWK.toJSONString());
        if (this.web3KeyPair != null) {
            System.out.printf("ecPrivateKey.S: %n%s%n", Hex.toHexString(this.ecPrivateKey.getS().toByteArray()));
        }
        byte[] encoded = point.getEncoded(false);
        byte[] x = this.point.normalize().getXCoord().getEncoded();
        byte[] y = this.point.normalize().getYCoord().getEncoded();
        System.out.printf("pioint: %n%s%n", Hex.toHexString(encoded));
        System.out.printf("pioint.x: %n%s%n", Hex.toHexString(x));
        System.out.printf("pioint.y: %n%s%n", Hex.toHexString(y));
        System.out.printf("publickey: %n%s%n", Hex.toHexString(this.publicKey.toByteArray()));
        //System.out.printf("address: %n%s%n", Hex.toHexString(this.address.getBytes()));
        System.out.printf("address: %n%s%n", this.address);
    }


    private BigInteger align2FieldSize(BigInteger s) {
        ECDomainParameters curv = new ECDomainParameters(CustomNamedCurves.getByName("secp256k1"));
        X9IntegerConverter x9 = new X9IntegerConverter();
        int fieldSize = x9.getByteLength(curv.getCurve());
        //System.out.printf("s.toByteArray().length: %n%d%n", s.toByteArray().length);
        //System.out.printf("fieldSize: %n%d%n", fieldSize);
        //System.out.printf("(length / fieldSize) * fieldSize: %n%d%n", (s.toByteArray().length / fieldSize) * fieldSize);
        byte[] sBytes = x9.integerToBytes(s, (s.toByteArray().length / fieldSize) * fieldSize);
        //System.out.printf("sBytes.length: %n%d%n", sBytes.length);
        //BigInteger b = BigIntegers.fromUnsignedByteArray(sBytes);
        BigInteger b = new BigInteger(1, sBytes);
        //System.out.printf("align2FieldSize convert: %n%s%n%s%n", Hex.toHexString(s.toByteArray()), Hex.toHexString(b.toByteArray()));
        return b;
    }

    public static void testWEB3() {
        System.out.println("WEB3 testing");
        WEB3 web1 = new WEB3();
        web1.printWeb3();
        web1 = new WEB3(web1.ecPrivateKey);
        web1.printWeb3();
        web1 = new WEB3(web1.nimbusdsJWK);
        web1.printWeb3();
        web1 = new WEB3(web1.publicKey);
        web1.printWeb3();
    }

    public static void printCurveParamByWeb3j() {
        // Retrieve the parameters from the ECKeyPair
        BigInteger a = Sign.CURVE_PARAMS.getCurve().getA().toBigInteger();
        BigInteger b = Sign.CURVE_PARAMS.getCurve().getB().toBigInteger();
        BigInteger p = Sign.CURVE_PARAMS.getCurve().getField().getCharacteristic();
        BigInteger gx = Sign.CURVE_PARAMS.getG().getAffineXCoord().toBigInteger();
        BigInteger gy = Sign.CURVE_PARAMS.getG().getAffineYCoord().toBigInteger();
        BigInteger n = Sign.CURVE_PARAMS.getN();
        int h = Sign.CURVE_PARAMS.getH().intValue();

        // Print the parameter values
        System.out.println("a: " + a);
        System.out.println("b: " + b);
        System.out.println("p: " + p);
        System.out.println("Gx: " + gx);
        System.out.println("Gy: " + gy);
        System.out.println("n: " + n);
        System.out.println("h: " + h);
    }

    public static void printCurveParamByNimbusds() {
        BigInteger a1 = Curve.SECP256K1.toECParameterSpec().getCurve().getA();
        BigInteger b1 = Curve.SECP256K1.toECParameterSpec().getCurve().getB();
        int filedBits = Curve.SECP256K1.toECParameterSpec().getCurve().getField().getFieldSize();
        BigInteger p1 = BigInteger.valueOf(2L).pow(filedBits)
                .subtract(BigInteger.valueOf(2L).pow(32))
                .subtract(BigInteger.valueOf(2L).pow(9))
                .subtract(BigInteger.valueOf(2L).pow(8))
                .subtract(BigInteger.valueOf(2L).pow(7))
                .subtract(BigInteger.valueOf(2L).pow(6))
                .subtract(BigInteger.valueOf(2L).pow(4))
                .subtract(BigInteger.ONE);
        
        BigInteger gx1 = Curve.SECP256K1.toECParameterSpec().getGenerator().getAffineX();
        BigInteger gy1 = Curve.SECP256K1.toECParameterSpec().getGenerator().getAffineY();
        BigInteger n1 = Curve.SECP256K1.toECParameterSpec().getOrder();
        //int h = Curve.SECP256K1.toECParameterSpec().get();
        //byte[] seed = Curve.SECP256K1.toECParameterSpec().getCurve().getSeed();
        // Print the parameter values
        BigInteger order = Curve.SECP256K1.toECParameterSpec().getOrder();
        BigInteger fieldSize = BigInteger.valueOf(2).pow(filedBits);

        BigInteger numberOfPoints = fieldSize.add(BigInteger.ONE).subtract(order);

        BigInteger cofactor = numberOfPoints.divide(order);
        System.out.println("a: " + a1);
        System.out.println("b: " + b1);
        System.out.println("p: " + p1);
        System.out.println("Gx: " + gx1);
        System.out.println("Gy: " + gy1);
        System.out.println("n: " + n1);
        System.out.println("filedBits: " + filedBits);
        System.out.println("h (Cofactor): " + cofactor);
    }

    public static void getTypeofPublicKey(BigInteger ecPublicKey) {
        // Get the uncompressed public key as byte array
        byte[] uncompressedPublicKey = Numeric.toBytesPadded(ecPublicKey, 64);

        // Get the first byte of the uncompressed public key
        byte type = uncompressedPublicKey[0];

        System.out.println("PublicKey hex string: " + Numeric.toHexString(uncompressedPublicKey));
        switch (type) {
            // infinity
            case 0x00: {
                System.out.println("ecPublicKey type is infinity");
                break;
            }
            // compressed
            case 0x02: 
            case 0x03: {
                System.out.println("ecPublicKey type is compressed");
                break;
            }
            // uncompressed
            case 0x04: {
                System.out.println("ecPublicKey type is uncompressed");
                break;
            }
            // hybrid
            case 0x06: 
            case 0x07: {
                System.out.println("ecPublicKey type is uncompressed");
                //p = validatePoint(X, Y);
                break;
            }
            default:
                System.out.println("ecPublicKey type is unknow");
        }
    }
}

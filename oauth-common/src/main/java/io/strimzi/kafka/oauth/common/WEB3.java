/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.math.BigInteger;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

/**
 * A class with methods for introspecting a JWT token
 */
public class WEB3 {

    private ECKey aliceJWK;
    private ECKeyPair ecKeyPair;
    public BigInteger pulicKey;
    public String address;

    /**
     * Create a new instance
     */
    public WEB3() {
        try {
            this.aliceJWK = new ECKeyGenerator(Curve.SECP256K1).generate();
            BigInteger alicePrivateKeyInt = aliceJWK.getD().decodeToBigInteger();
            this.ecKeyPair = ECKeyPair.create(alicePrivateKeyInt);
            this.pulicKey = getPublicKey();
            this.address = getAddress();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public WEB3(ECKey aliceJWK) {
        BigInteger alicePrivateKeyInt = aliceJWK.getD().decodeToBigInteger();
        this.ecKeyPair = ECKeyPair.create(alicePrivateKeyInt);
        this.pulicKey = getPublicKey();
        this.address = getAddress();
    }

    private BigInteger getPublicKey() {
        return this.ecKeyPair.getPublicKey();
    }

    private String getAddress() {
        return Keys.getAddress(this.ecKeyPair.getPublicKey());
    }

}

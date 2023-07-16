/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.validator;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.strimzi.kafka.oauth.common.JSONUtil;
import io.strimzi.kafka.oauth.common.TimeUtil;
import io.strimzi.kafka.oauth.common.TokenInfo;
import io.strimzi.kafka.oauth.common.WEB3;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import static io.strimzi.kafka.oauth.validator.TokenValidationException.Status;

/**
 * This class is responsible for validating the JWT token signatures during session authentication.
 * <p>
 * It performs fast local token validation without the need to immediately contact the authorization server.
 * for that it relies on the JWKS endpoint exposed at authorization server, which is a standard OAuth2 public endpoint
 * containing the information about public keys that can be used to validate JWT signatures.
 * </p>
 * <p>
 * A single threaded refresh job is run periodically or upon detecting an unknown signing key, that fetches the latest trusted public keys
 * for signature validation from authorization server. If the refresh job is unsuccessful it employs the so called 'exponential back-off'
 * to retry later in order to reduce any out-of-sync time with the authorization server while still not flooding the server
 * with endless consecutive requests.
 * </p>
 */
public class AccessValidator {

    private static final Logger log = LoggerFactory.getLogger(JWTSignatureValidator.class);
    private final String token;
    private final boolean checkETHPayment;
    private WEB3 web3;
    private JsonNode payload;

    @SuppressWarnings("checkstyle:ParameterNumber")
    public AccessValidator(String token,
                           boolean checkETHPayment) {
        this.token = token;
        this.checkETHPayment = checkETHPayment;
        this.web3 = null;
        this.payload = null;
    }

    public boolean ethValidate() {
        if (!checkETHPayment) {
            return true;
        }

        return true;
    }

    @SuppressFBWarnings(value = "BC_UNCONFIRMED_CAST_OF_RETURN_VALUE",
            justification = "We tell TokenVerifier to parse AccessToken. It will return AccessToken or fail.")
    public boolean signatureValidate() {

        SignedJWT jwt;
        JWK publicKey;
        try {
            jwt = SignedJWT.parse(token);
        } catch (Exception e) {
            throw new TokenValidationException("Token validation failed: Failed to parse JWT.", e)
                    .status(Status.INVALID_TOKEN);
        }

        JsonNode t;
        try {
            publicKey = jwt.getHeader().getJWK();
            if (publicKey == null) {
                throw new TokenValidationException("Token validation failed: Unknown publicKey" + publicKey);
            }

            if (publicKey instanceof ECKey) {
                if (!jwt.verify(new ECDSAVerifier((ECKey) publicKey))) {
                    throw new TokenSignatureException("Signature check failed: Invalid token signature");
                }
            } else {
                return false;
            }

            t = JSONUtil.asJson(jwt.getPayload().toJSONObject());
        } catch (TokenValidationException e) {
            // just rethrow
            throw e;
        } catch (Exception e) {
            throw new TokenValidationException("Token validation failed", e);
        }

        validateTokenPayload(t);
        this.payload = t;
        this.web3 = WEB3.publicWEB3(publicKey);
        return true;
    }

    public JsonNode getPayload() {
        return this.payload;
    }

    public WEB3 getWeb3() {
        return this.web3;
    }

    private ECKey getPublicKey(String id) {
        ECKey ecPublicJWK = null;
        try {
            ecPublicJWK = ECKey.parse(id);
        } catch (java.text.ParseException e) {
            ecPublicJWK = null;
        }
        return ecPublicJWK;
    }


    private void validateTokenPayload(JsonNode t) {
        JsonNode exp = t.get(TokenInfo.EXP);
        if (exp == null) {
            throw new TokenValidationException("Token validation failed: Expiry not set");
        }

        long expiresMillis = exp.asInt(0) * 1000L;
        if (System.currentTimeMillis() > expiresMillis) {
            throw new TokenExpiredException("Token expired at: " + expiresMillis + " (" +
                    TimeUtil.formatIsoDateTimeUTC(expiresMillis) + " UTC)");
        }
    }
}

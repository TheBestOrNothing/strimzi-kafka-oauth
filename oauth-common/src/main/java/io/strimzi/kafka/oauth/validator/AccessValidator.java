/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.validator;

import com.nimbusds.jose.JWSVerifier;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static io.strimzi.kafka.oauth.validator.TokenValidationException.Status;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Map;
import org.json.JSONObject;
import org.json.JSONArray;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.Response;


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
    private final boolean ethValidation;
    private WEB3 web3;
    private JsonNode payload;

    @SuppressWarnings("checkstyle:ParameterNumber")
    public AccessValidator(String token,
                           boolean ethValidation) {
        this.token = token;
        this.ethValidation = ethValidation;
        this.web3 = null;
        this.payload = null;
    }

    public boolean ethValidate(Map<String, BigInteger> whiteList, Map<String, BigInteger> blackList, String provider, String adminAdress, String whispeerAdress) {

        boolean status = false;
        long current = System.currentTimeMillis() / 1000;
        String address = this.web3.address;

        if (!ethValidation) {
            return true;
        }

        if (blackList.get(address) != null) {
            log.debug("Reject hacker to access the kafka broker {} ", address);
            return false;
        }

        BigInteger expirationTime = whiteList.get(address);
        if (expirationTime != null && expirationTime.longValue() >= current) {
            log.debug("{} have been in the whiteList, no need to validate again", address);
            return true;
        }

        if (!WEB3.checkProvider(provider)) {
            log.debug("Failure to validate API key {} ", provider);
            return false;
        }

        //If there is no specified user(address) in the whiteList,
        //the expirationTime of the user should be retrieved from the smart contract
        Function function = new Function(
                "getExpirationTime",
                Collections.singletonList(new Address(address)), // Function parameters
                Collections.singletonList(new org.web3j.abi.TypeReference<org.web3j.abi.datatypes.generated.Uint256>() { })); // Return type

        String encodedFunction = FunctionEncoder.encode(function);

        //from = admin; to = whispeerAddress; data = encodedFunction;
        //Transaction transaction = new Transaction(adminAdress, null, null, null, whispeerAdress, null, encodedFunction, null, null, null);
        String body = null;
        AsyncHttpClient client = new DefaultAsyncHttpClient();

        // Create the innermost JSON object
        JSONObject innerObject = new JSONObject();
        innerObject.put("to", whispeerAdress);
        innerObject.put("from", adminAdress);
        innerObject.put("data", encodedFunction);

        // Create the JSON array for "params" and add the inner object and the string
        JSONArray paramsArray = new JSONArray();
        paramsArray.put(innerObject);
        paramsArray.put("latest");

        // Create the outer JSON object
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", 1);
        jsonObject.put("jsonrpc", "2.0");
        jsonObject.put("method", "eth_call");
        jsonObject.put("params", paramsArray);

        body = jsonObject.toString();
        System.out.println(jsonObject.toString());
        
        try {

            Response response = client.prepare("POST", provider)
                      .setHeader("accept", "application/json")
                      .setHeader("content-type", "application/json")
                      .setBody(body)
                      .execute()
                      .toCompletableFuture()
                      .join();

            if (response.getStatusCode() == 200) {
                String responseStr = response.getResponseBody();
                System.out.println("Response: " + responseStr);
                status = true;

                // Parse the JSON response using org.json.JSONObject
                JSONObject responseJson = new JSONObject(responseStr);

                // Get the "result" value as a hexadecimal string
                String resultHex = responseJson.getString("result");

                // Convert the hexadecimal string to a BigInteger
                expirationTime = new BigInteger(resultHex.substring(2), 16);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        System.out.println("User's expiration time: " + expirationTime);
        System.out.println("Current system time: " + current);
        if (expirationTime != null && expirationTime.longValue() >= current) {
            whiteList.put(address, expirationTime);
            status = true;
        } else {
            //Add the web3.address to the blackList, because one client must check the expirationTime by self.
            //If the expirationTime < current, it means hackers try to attack the kafka server.
            blackList.put(address, new BigInteger("10"));
            log.debug("Hacker {} try to attack the kafka broker", address);
            status = false;
        }

        return status;
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
                JWSVerifier verifier = new ECDSAVerifier((ECKey) publicKey);
                verifier.getJCAContext().setProvider(new BouncyCastleProvider());
                if (!jwt.verify(verifier)) {
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

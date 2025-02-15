/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

//import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
//import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Date;


/**
 * An example consumer implementation
 */
//@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class KafkaAdminToken {

    /**
     * A main method
     *
     * @param args No arguments expected
     */
    public static void main(String[] args) {

        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMR25qdjVWVXdfdXFJd0QxZGtlQnlRTHY1SEVOaDk1bldTaU5oNDBZNW1BIn0.eyJleHAiOjE2ODM3MTM4NzUsImlhdCI6MTY4MzY3Nzg3NSwianRpIjoiY2U3YjRmYzItNWNkMS00ZDE5LTkyNjUtM2MzOGRhNDI0NTU0IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsImF1ZCI6ImthZmthIiwic3ViIjoiODQzZTA3MGEtNjA0MC00Mzk1LWI0MzAtMzllOWE5MzE4OWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoia2Fma2EtcHJvZHVjZXItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsia2Fma2EiOnsicm9sZXMiOlsia2Fma2EtdG9waWM6c3VwZXJhcHBfKjpvd25lciJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIn0.DBAq67KF9rfNVEy3L1nhaiHQIGXWBNlOW8QTRhNH1NTJ0DqZ_grFCLeckkVbr8BXSVWLHj39mx1ZCYU_1AIZB-0i8riRhqT1T5bgpAv2MkutmQEWd2FpiC5IVK1q8Vyw0bo2MDQInvjUQn9tB4NBNNzogDaBNRmatUD-m2y3tAJ3T-sl4fiaMXX6bzaf55r4LfwVYkP0TyeBzQoXCyUtPlP2ECKWMt6A4MTjT6ysfE7Odmk_VGploUzhSMG_BEIGcA8tFcYx4nWjV8f5PaIwpz8cmBlZBQjnfU4gnKk1U-cl6gb3EMtu9YLiqGY8ktx0P5QOm4q8h5TRd5dtuFIBHg";
        getToken(token);
    }

    private static String getToken(String token) {
        // Generate EC key pair on the secp256k1 curve
        try {
            // Parse token string into a SignedJWT object
            SignedJWT signedJWT = SignedJWT.parse(token);
//            System.out.println(signedJWT.getHeader().toJSONObject());
            JWSHeader header = signedJWT.getHeader();
            
            //Create resource_access add to the jwt
            String resourceAccess = "[{\"scopes\":[\"Alter\",\"Read\",\"Describe\",\"Delete\",\"Write\",\"Create\",\"AlterConfigs\",\"DescribeConfigs\"],\"rsid\":\"f7bd27d0-e669-47dc-acc4-568c74332976\",\"rsname\":\"Topic:a_*\"},{\"scopes\":[\"Describe\",\"Write\"],\"rsid\":\"a7cf3178-110a-4165-9c86-fa8cdd8d4438\",\"rsname\":\"Topic:x_*\"},{\"scopes\":[\"Read\",\"Describe\"],\"rsid\":\"2dc8e81e-1b25-4537-b5c1-b8f782678336\",\"rsname\":\"Group:a_*\"},{\"scopes\":[\"IdempotentWrite\"],\"rsid\":\"d42b5bc3-6d68-4789-91e5-6f34f7ac9ab7\",\"rsname\":\"kafka-cluster:my-cluster,Cluster:*\"}]";
            ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                .keyID(header.getKeyID())
                .generate();

            // Get the public EC key, for recipients to validate the signatures
            ECKey ecPublicJWK = ecJWK.toPublicJWK();
            
            // Get JWTClaimsSet object from SignedJWT
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            // Create a new JWTClaimsSet object with updated expiration time
            Date newExpirationTime = new Date(System.currentTimeMillis() + 3600 * 1000 * 7 * 24); // 1 hour from now
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
            builder.expirationTime(newExpirationTime);
            builder.claim("gitcoins", resourceAccess);
//            String publicKey = ecJWK.toPublicJWK().toString();
//            String publicKey = ecJWK.toPublicJWK().toJSONString();
//            ECKey publicJWK = ECKey.parse(publicKey);
//            builder.claim("publicKey", publicKey);
//            builder.issuer(publicKey);
            JWTClaimsSet newClaimsSet = builder.build();
            
            // Create JWT for ES256K alg
            SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256K)
                    .keyID(ecJWK.getKeyID())
                    .type(header.getType())
                    .jwk(ecPublicJWK)
                    .build(),
                    newClaimsSet);

            // Sign with private EC key
            jwt.sign(new ECDSASigner(ecJWK));

            // Output the JWT
            token = jwt.serialize();
//            System.out.println(publicKey);
//            System.out.println(ecJWK.getKeyID());
//            System.out.println("Token:");
            System.out.println(token);

            // Verify the ES256K signature with the public EC key
//            System.out.println(jwt.verify(new ECDSAVerifier(ecPublicJWK)));
//            System.out.println(jwt.getHeader().getKeyID());
//            System.out.println(jwt.getHeader().toJSONObject());
//            System.out.println(jwt.getJWTClaimsSet().toJSONObject());

        } catch (JOSEException | ParseException e) {
            System.out.println("Exception Occure");
        }

        return token;
    }
}

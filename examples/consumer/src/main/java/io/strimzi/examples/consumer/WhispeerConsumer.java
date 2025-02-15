/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.examples.consumer;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.strimzi.kafka.oauth.client.ClientConfig;
import io.strimzi.kafka.oauth.common.Config;
import io.strimzi.kafka.oauth.common.ConfigProperties;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.errors.AuthorizationException;
import org.apache.kafka.common.errors.InterruptException;
import org.apache.kafka.common.serialization.StringDeserializer;

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

import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;

/**
 * An example consumer implementation
 */
@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class WhispeerConsumer {

    /**
     * A main method
     *
     * @param args No arguments expected
     */
    public static void main(String[] args) {

        String topic = "a_Topic1";

        Properties defaults = new Properties();
        Config external = new Config();

        //  Set KEYCLOAK_HOST to connect to Keycloak host other than 'keycloak'
        //  Use 'keycloak.host' system property or KEYCLOAK_HOST env variable

        final String keycloakHost = external.getValue("keycloak.host", "keycloak");
        final String realm = external.getValue("realm", "demo");
        final String tokenEndpointUri = "http://" + keycloakHost + ":8080/auth/realms/" + realm + "/protocol/openid-connect/token";

        //  You can also configure token endpoint uri directly via 'oauth.token.endpoint.uri' system property,
        //  or OAUTH_TOKEN_ENDPOINT_URI env variable

        defaults.setProperty(ClientConfig.OAUTH_TOKEN_ENDPOINT_URI, tokenEndpointUri);

        //  By defaut this client uses preconfigured clientId and secret to authenticate.
        //  You can set OAUTH_ACCESS_TOKEN or OAUTH_REFRESH_TOKEN to override default authentication.
        //
        //  If access token is configured, it is passed directly to Kafka broker
        //  If refresh token is configured, it is used in conjunction with clientId and secret
        //
        //  See examples README.md for more info.

        //final String accessToken = external.getValue(ClientConfig.OAUTH_ACCESS_TOKEN, null);
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMR25qdjVWVXdfdXFJd0QxZGtlQnlRTHY1SEVOaDk1bldTaU5oNDBZNW1BIn0.eyJleHAiOjE2ODM3MTM4NzUsImlhdCI6MTY4MzY3Nzg3NSwianRpIjoiY2U3YjRmYzItNWNkMS00ZDE5LTkyNjUtM2MzOGRhNDI0NTU0IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsImF1ZCI6ImthZmthIiwic3ViIjoiODQzZTA3MGEtNjA0MC00Mzk1LWI0MzAtMzllOWE5MzE4OWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoia2Fma2EtcHJvZHVjZXItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsia2Fma2EiOnsicm9sZXMiOlsia2Fma2EtdG9waWM6c3VwZXJhcHBfKjpvd25lciJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIn0.DBAq67KF9rfNVEy3L1nhaiHQIGXWBNlOW8QTRhNH1NTJ0DqZ_grFCLeckkVbr8BXSVWLHj39mx1ZCYU_1AIZB-0i8riRhqT1T5bgpAv2MkutmQEWd2FpiC5IVK1q8Vyw0bo2MDQInvjUQn9tB4NBNNzogDaBNRmatUD-m2y3tAJ3T-sl4fiaMXX6bzaf55r4LfwVYkP0TyeBzQoXCyUtPlP2ECKWMt6A4MTjT6ysfE7Odmk_VGploUzhSMG_BEIGcA8tFcYx4nWjV8f5PaIwpz8cmBlZBQjnfU4gnKk1U-cl6gb3EMtu9YLiqGY8ktx0P5QOm4q8h5TRd5dtuFIBHg";
        final String accessToken = getToken(token);
        System.out.println(accessToken);
        defaults.setProperty(ClientConfig.OAUTH_ACCESS_TOKEN, accessToken);

        if (accessToken == null) {
            defaults.setProperty(Config.OAUTH_CLIENT_ID, "kafka-consumer-client");
            defaults.setProperty(Config.OAUTH_CLIENT_SECRET, "kafka-consumer-client-secret");
        }

        // Use 'preferred_username' rather than 'sub' for principal name
        if (isAccessTokenJwt(external)) {
            defaults.setProperty(Config.OAUTH_USERNAME_CLAIM, "preferred_username");
        }

        // Resolve external configurations falling back to provided defaults
        ConfigProperties.resolveAndExportToSystemProperties(defaults);
        Properties props = buildConsumerConfig(defaults);

        //Properties props = buildConsumerConfig();
        Consumer<String, String> consumer = new KafkaConsumer<>(props);

        for (int i = 0; ; i++) {
            try {
                consumer.subscribe(Arrays.asList(topic));

                while (true) {
                    ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
                    for (ConsumerRecord<String, String> record : records) {
                        System.out.println("Consumed message - " + i + ": " + record.value());
                    }
                }
            } catch (InterruptException e) {
                throw new RuntimeException("Interrupted while consuming message - " + i + "!");

            } catch (AuthenticationException | AuthorizationException e) {
                consumer.close();
                consumer = new KafkaConsumer<>(props);
            }
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean isAccessTokenJwt(Config config) {
        String legacy = config.getValue(Config.OAUTH_TOKENS_NOT_JWT);
        if (legacy != null) {
            System.out.println("[WARN] Config option 'oauth.tokens.not.jwt' is deprecated. Use 'oauth.access.token.is.jwt' (with reverse meaning) instead.");
        }
        return legacy != null ? !Config.isTrue(legacy) :
                config.getValueAsBoolean(Config.OAUTH_ACCESS_TOKEN_IS_JWT, true);
    }

    /**
     * Build KafkaConsumer properties. The specified values are defaults that can be overridden
     * through runtime system properties or env variables.
     *
     * @return Configuration properties
     */
    private static Properties buildConsumerConfig(Properties p) {

        //Properties p = new Properties();

        p.setProperty("security.protocol", "SASL_PLAINTEXT");
        p.setProperty("sasl.mechanism", "OAUTHBEARER");
        p.setProperty("sasl.jaas.config", "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;");
        p.setProperty("sasl.login.callback.handler.class", "io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler");

        p.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        p.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        p.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());

        p.setProperty(ConsumerConfig.GROUP_ID_CONFIG, "a_consumer-group");
        p.setProperty(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, "10");
        p.setProperty(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true");

        return ConfigProperties.resolve(p);
    }

    private static String getToken(String token) {
        // Generate EC key pair on the secp256k1 curve
        try {
            // Parse token string into a SignedJWT object
            SignedJWT signedJWT = SignedJWT.parse(token);
            System.out.println(signedJWT.getHeader().toJSONObject());
            JWSHeader header = signedJWT.getHeader();
            
            //Create resource_access add to the jwt
            String resourceAccess = "[{\"scopes\":[\"Alter\",\"Read\",\"Describe\",\"Delete\",\"Write\",\"Create\",\"AlterConfigs\",\"DescribeConfigs\"],\"rsid\":\"f7bd27d0-e669-47dc-acc4-568c74332976\",\"rsname\":\"Topic:a_*\"},{\"scopes\":[\"Describe\",\"Write\"],\"rsid\":\"a7cf3178-110a-4165-9c86-fa8cdd8d4438\",\"rsname\":\"Topic:x_*\"},{\"scopes\":[\"Read\",\"Describe\"],\"rsid\":\"2dc8e81e-1b25-4537-b5c1-b8f782678336\",\"rsname\":\"Group:a_*\"},{\"scopes\":[\"IdempotentWrite\"],\"rsid\":\"d42b5bc3-6d68-4789-91e5-6f34f7ac9ab7\",\"rsname\":\"kafka-cluster:my-cluster,Cluster:*\"}]";
            ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                              .keyID("consumer1")
                              .generate();
            

            // Get the public EC key, for recipients to validate the signatures
            ECKey ecPublicJWK = ecJWK.toPublicJWK();

            // Get JWTClaimsSet object from SignedJWT
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            // Create a new JWTClaimsSet object with updated expiration time
            Date newExpirationTime = new Date(System.currentTimeMillis() + 3600 * 1000); // 1 hour from now
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
            builder.expirationTime(newExpirationTime);
            builder.claim("gitcoins", resourceAccess);
            JWTClaimsSet newClaimsSet = builder.build();
            
            // Create JWT for ES256K alg
            SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256K)
                    .keyID(ecJWK.getKeyID())
                    .type(header.getType())
                    .build(),
                    newClaimsSet);

            // Sign with private EC key
            jwt.sign(new ECDSASigner(ecJWK));

            // Output the JWT
            token = jwt.serialize();
            System.out.println(token);

            // Verify the ES256K signature with the public EC key
            System.out.println(jwt.verify(new ECDSAVerifier(ecPublicJWK)));

            System.out.println(jwt.getJWTClaimsSet().toJSONObject());

        } catch (JOSEException | ParseException e) {
            System.out.println("Exception Occure");
        }

        return token;
    }
}

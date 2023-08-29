/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.examples.consumer;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.strimzi.kafka.oauth.client.ClientConfig;
import io.strimzi.kafka.oauth.common.Config;
import io.strimzi.kafka.oauth.common.ConfigProperties;
import io.strimzi.kafka.oauth.common.End2EndEncryption;
//import io.strimzi.kafka.oauth.common.SECP256K1;
import io.strimzi.kafka.oauth.common.WEB3;

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
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
//import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
//import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static io.strimzi.kafka.oauth.common.LogUtil.mask;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * An example consumer implementation
 */
@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class Bob {

    /**
     * A main method
     *
     * @param args No arguments expected
     */
    public static void main(String[] args) {

        // Register BouncyCastleProvider
        BouncyCastleProvider bcProvider = new BouncyCastleProvider();

        System.out.println("bcProvider.getInfo(): " + bcProvider.getInfo());
        Package bcPackage = bcProvider.getClass().getPackage();

        // Print the artifactId and version
        System.out.println("Artifact ID: " + bcPackage.getImplementationTitle());
        System.out.println("Version: " + bcPackage.getImplementationVersion());
        System.out.println(bcPackage.getImplementationVendor());
        System.out.println(bcPackage.getName());
        System.out.println(bcPackage.getSpecificationTitle());
        System.out.println(bcPackage.getSpecificationVendor());
        System.out.println(bcPackage.getSpecificationVersion());
        
        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Package jssePackage = jsseProvider.getClass().getPackage();
        System.out.println(jssePackage.getImplementationVendor());
        System.out.println(jssePackage.getName());
        System.out.println(jssePackage.getSpecificationTitle());
        System.out.println(jssePackage.getSpecificationVendor());
        System.out.println(jssePackage.getSpecificationVersion());

        //Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        // Register BouncyCastleProvider
        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println("Name: " + provider.getName());
            System.out.println("Version: " + provider.toString());
            System.out.println("Info: " + provider.getInfo());
            System.out.println("-----------------------------------------");
        }

        Properties defaults = new Properties();
        Config external = new Config();

        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream("alicebob.properties")) {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // Retrieve values using property keys
        String alchemyProvider = properties.getProperty("alchemyProvider");
        if (alchemyProvider == null) {
            System.out.println("alchemyProvider is null, please adapt the whispeer.properties file");
        }

        String bobPrivateKeyStr = properties.getProperty("bobPrivate");
        String alicePublicKeyStr = properties.getProperty("alicePublic");
        
        BigInteger bobPrivateKeyBig = new BigInteger(bobPrivateKeyStr, 16);
        WEB3 bob = new WEB3(bobPrivateKeyBig);
        bob.printWeb3();
        
        BigInteger alicePublicKeyBig = new BigInteger(alicePublicKeyStr, 16);
        WEB3 alicePublic = WEB3.publicWEB3(alicePublicKeyBig);
        alicePublic.printWeb3();
        String topic = bob.address;

        //final String accessToken = external.getValue(ClientConfig.OAUTH_ACCESS_TOKEN, null);
        final String accessToken = getToken(bob);
        System.out.println(accessToken);
        defaults.setProperty(ClientConfig.OAUTH_ACCESS_TOKEN, accessToken);


        // Resolve external configurations falling back to provided defaults
        ConfigProperties.resolveAndExportToSystemProperties(defaults);
        Properties props = buildConsumerConfig(defaults);

        //Properties props = buildConsumerConfig();
        Consumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList(topic));
        //SECP256K1 secp256k1 = new SECP256K1();
        End2EndEncryption e2ee = new End2EndEncryption(alicePublic.nimbusdsJWK, bob.nimbusdsJWK);

        for (int i = 0; ; i++) {
            try {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(10));
                for (ConsumerRecord<String, String> record : records) {
                    System.out.println("Consumed message - " + i + ": " + e2ee.token2Message(record.value()));
                }
            } catch (InterruptException e) {
                throw new RuntimeException("Interrupted while consuming message - " + i + "!");

            } catch (AuthenticationException | AuthorizationException e) {
                consumer.close();
                consumer = new KafkaConsumer<>(props);
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                throw new RuntimeException("Interrupted while sleeping!");
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

        p.setProperty("security.protocol", "SASL_SSL");
        //p.setProperty("security.providers", "org.bouncycastle.jce.provider.BouncyCastleProvider,org.bouncycastle.jsse.provider.BouncyCastleJsseProvider");
        p.setProperty("sasl.mechanism", "OAUTHBEARER");
        p.setProperty("sasl.jaas.config", "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;");
        p.setProperty("sasl.login.callback.handler.class", "io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler");

        p.setProperty("sasl.login.refresh.buffer.seconds", "300");
        p.setProperty("sasl.login.refresh.min.period.seconds", "300");
        p.setProperty("sasl.login.refresh.window.factor", "0.8");
        p.setProperty("sasl.login.refresh.window.jitter", "0.05");

        p.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "ubuntu:9092");
        p.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        p.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());

        p.setProperty(ConsumerConfig.GROUP_ID_CONFIG, "consumer-group");
        p.setProperty(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, "10");
        p.setProperty(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true");

        //p.setProperty("ssl.cipher.suites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        p.setProperty("ssl.keymanager.algorithm", "PKIX");
        p.setProperty("ssl.trustmanager.algorithm", "PKIX");
        p.setProperty("ssl.keystore.type", "PKCS12");
        p.setProperty("ssl.truststore.type", "PKCS12");
        p.setProperty("ssl.truststore.location", "/tmp/ssl/client.truststore.jks");
        p.setProperty("ssl.truststore.password", "client-truststore-pass");
        p.setProperty("ssl.keystore.location", "/tmp/ssl/client.keystore.jks");
        p.setProperty("ssl.keystore.password", "client-keystore-pass");
        p.setProperty("ssl.key.password", "client-keystore-pass");
        p.setProperty("ssl.enabled.protocols", "TLSv1.2,TLSv1.1,TLSv1");
        p.setProperty("ssl.client.auth", "required");
        //p.setProperty("ssl.endpoint.identification.algorithm", "https");
        p.setProperty("ssl.endpoint.identification.algorithm", "https");

        return ConfigProperties.resolve(p);
    }

    private static String getToken(WEB3 bob) {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMR25qdjVWVXdfdXFJd0QxZGtlQnlRTHY1SEVOaDk1bldTaU5oNDBZNW1BIn0.eyJleHAiOjE2ODM3MTM4NzUsImlhdCI6MTY4MzY3Nzg3NSwianRpIjoiY2U3YjRmYzItNWNkMS00ZDE5LTkyNjUtM2MzOGRhNDI0NTU0IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMvZGVtbyIsImF1ZCI6ImthZmthIiwic3ViIjoiODQzZTA3MGEtNjA0MC00Mzk1LWI0MzAtMzllOWE5MzE4OWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoia2Fma2EtcHJvZHVjZXItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsia2Fma2EiOnsicm9sZXMiOlsia2Fma2EtdG9waWM6c3VwZXJhcHBfKjpvd25lciJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImI5NDJlMzE2LTllNmQtNGEwNy04MDExLWViZmY0YTg1NWQ0MiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIn0.DBAq67KF9rfNVEy3L1nhaiHQIGXWBNlOW8QTRhNH1NTJ0DqZ_grFCLeckkVbr8BXSVWLHj39mx1ZCYU_1AIZB-0i8riRhqT1T5bgpAv2MkutmQEWd2FpiC5IVK1q8Vyw0bo2MDQInvjUQn9tB4NBNNzogDaBNRmatUD-m2y3tAJ3T-sl4fiaMXX6bzaf55r4LfwVYkP0TyeBzQoXCyUtPlP2ECKWMt6A4MTjT6ysfE7Odmk_VGploUzhSMG_BEIGcA8tFcYx4nWjV8f5PaIwpz8cmBlZBQjnfU4gnKk1U-cl6gb3EMtu9YLiqGY8ktx0P5QOm4q8h5TRd5dtuFIBHg";

        // Generate EC key pair on the secp256k1 curve
        try {
            // Parse token string into a SignedJWT object
            SignedJWT signedJWT = SignedJWT.parse(token);
            System.out.println(signedJWT.getHeader().toJSONObject());
            JWSHeader header = signedJWT.getHeader();
            
            //Create resource_access add to the jwt
            ECKey ecJWK = bob.nimbusdsJWK;
            

            // Get the public EC key, for recipients to validate the signatures
            ECKey ecPublicJWK = ecJWK.toPublicJWK();

            // Get JWTClaimsSet object from SignedJWT
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            // Create a new JWTClaimsSet object with updated expiration time
            Date newExpirationTime = new Date(System.currentTimeMillis() + 3600 * 1000); // 1 hour from now
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
            builder.expirationTime(newExpirationTime);
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
            ECDSASigner signer = new ECDSASigner(ecJWK);
            signer.getJCAContext().setProvider(new BouncyCastleProvider());
            jwt.sign(signer);

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
    
    public static void debugJWT(String token) {
        JWSObject jws;
        try {
            jws = JWSObject.parse(token);
            System.out.printf("Token : %s%n", token);
            System.out.printf("Token Header: %s%n", jws.getHeader().toString());
            System.out.printf("Token Payload: %s%n", jws.getPayload().toString());
        } catch (Exception e) {
            System.out.printf("[IGNORED] Token doesn't seem to be JWT token: " + mask(token));
            return;
        }
    }
}

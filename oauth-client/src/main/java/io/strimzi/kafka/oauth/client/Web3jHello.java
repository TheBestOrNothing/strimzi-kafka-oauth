/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Strings;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
/**
 * An example consumer implementation
 */
//@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class Web3jHello {

    /**
     * A main method
     *
     * @param args No arguments expected
     */
    public static void main(String[] args) {

        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream("hello.properties")) {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // Retrieve values using property keys
        String alchemyProvider = properties.getProperty("alchemyProvider");
        System.out.println(alchemyProvider);
        String alice = properties.getProperty("alicePrivateKey");
        System.out.println(alice);
        String helloContractAddress = properties.getProperty("helloContractAddress");
        System.out.println(helloContractAddress);
        
        try {
            //Step1: code, compile, unit test, and deployment one smart contract in Remix:

            //Step2: to generate the wrapper code, compile your smart contract:
            // $ solc Whispeer.sol --bin --abi --optimize -o .

            //Step3: then generate the wrapper code using the Web3j CLI:
            // $ web3j generate solidity -b Whispeer.bin  -a Whispeer.abi -o . -p io.strimzi.kafka.oauth.client
            // cp Whispeer.java ~/kafka/whispeer-kafka-oauth/oauth-client/src/main/java/io/strimzi/kafka/oauth/client/

            //Step4: Now you can create and deploy your smart contract:

            //Step5: Create Web3j and Credentials to load the hello contract
            Web3j web3j = Web3j.build(new HttpService(alchemyProvider));  
            Credentials credentials = Credentials.create(alice);

            //This command is just use org.web3j.utils to fix the following error
            // [ERROR] Unused declared dependencies found:
            // [ERROR]    org.web3j:utils:jar:4.9.8:compile
            System.out.println(Strings.isEmpty("0xb148b74d56a47cb2c2a789fe56e99aac5171f2ce"));

            HelloWorld hello = HelloWorld.load(helloContractAddress, web3j, credentials, new DefaultGasProvider());
            System.out.println(hello.helloWorld().send());
            hello.setText("testing").send();
            System.out.println(hello.helloWorld().send());
            web3j.shutdown();
        } catch (Exception e) {
            System.out.println("Exception Occure");
            e.printStackTrace();
        }
    }
}

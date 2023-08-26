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
            //Step1: create smart contract in Remix

            //Step2: compile, unit test, and deployment the smart contract by Remix

            //Step3: generate the java wrapper code
            //Step3.1: create the bin and abi of contract
            // $ solc Whispeer.sol --bin --abi --optimize -o .

            //Step3.2: create the wrapper code using the Web3j CLI:
            // $ web3j generate solidity -b Whispeer.bin  -a Whispeer.abi -o . -p io.strimzi.kafka.oauth.client
            // cp Whispeer.java ~/kafka/whispeer-kafka-oauth/oauth-client/src/main/java/io/strimzi/kafka/oauth/client/

            //Step4: create Web3j and Credentials for loading the Hello by contract address which have been deployed on ETH by step2
            Web3j web3j = Web3j.build(new HttpService(alchemyProvider));  
            Credentials credentials = Credentials.create(alice.trim());
            HelloWorld hello = HelloWorld.load(helloContractAddress, web3j, credentials, new DefaultGasProvider());
            
            //Step5: call the contract function by wrapper
            System.out.println(hello.helloWorld().send());
            hello.setText("testing").send();
            System.out.println(hello.helloWorld().send());
            
            //Step6: Bug fixing to load the org.web3.utils
            //This command is just use org.web3j.utils to fix the following error
            // [ERROR] Unused declared dependencies found:
            // [ERROR]    org.web3j:utils:jar:4.9.8:compile
            System.out.println(Strings.isEmpty("0xb148b74d56a47cb2c2a789fe56e99aac5171f2ce"));

            //Step7: shutdown the web3j provider
            web3j.shutdown();
        } catch (Exception e) {
            System.out.println("Exception Occure");
            e.printStackTrace();
        }
    }
}

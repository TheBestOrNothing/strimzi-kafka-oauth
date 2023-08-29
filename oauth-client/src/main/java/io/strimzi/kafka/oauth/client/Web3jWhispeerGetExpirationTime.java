/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

//import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import  org.web3j.protocol.core.methods.response.EthCall;

import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * An example consumer implementation
 */
//@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class Web3jWhispeerGetExpirationTime {

    /**
     * A main method
     *
     * @param args No arguments expected
     */
    public static void main(String[] args) {
        
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream("whispeer.properties")) {
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
        String adminPrivateKey = properties.getProperty("adminPrivate");
        String whispeerContractAddress = properties.getProperty("whispeerAddress");
        String aliceAddress = properties.getProperty("aliceAddress");
        String adminAddress = properties.getProperty("adminAddress");

        try {
            //create Web3j
            Web3j web3j = Web3j.build(new HttpService(alchemyProvider));

            /*
             * There are two way to get info from contract which have been deployed in the ETH
             * 
             * One way require private key and credentials to construct Whispeer.
             * It is very easy to get and set contract status, but the private key will be exposed.
             * please see the detailed code in the getExpirationTimeWithAdminPrivateKey function.
             * 
             * The other way is read only, no private key and credentials required.
             * Because the gas not required when read and retrieve info from any contract. 
             * It is harder and raw way to create an transaction, but no private key will be exposed.
             * please see the detailed code in the getExpirationTimeWithAdminAddress function.
             * 
             */
            
            getExpirationTimeWithAdminPrivateKey(web3j, whispeerContractAddress, adminPrivateKey, aliceAddress);

            getExpirationTimeWithAdminAddress(web3j, whispeerContractAddress, adminAddress, aliceAddress);

            web3j.shutdown();
        } catch (Exception e) {
            System.out.println("Exception Occure");
            e.printStackTrace();
        }
    }
    
    private static void getExpirationTimeWithAdminPrivateKey(Web3j web3j, String whispeerContractAddress, String adminPrivateKey, String aliceAddress) {
        //Step1: create smart contract in Remix

        //Step2: compile, unit test, and deployment the smart contract by Remix

        //Step3: generate the java wrapper code
        //Step3.1: create the bin and abi of contract
        // $ solc Whispeer.sol --bin --abi --optimize -o .

        //Step3.2: create the wrapper code using the Web3j CLI:
        // $ web3j generate solidity -b Whispeer.bin  -a Whispeer.abi -o . -p io.strimzi.kafka.oauth.client
        // cp Whispeer.java ~/kafka/whispeer-kafka-oauth/oauth-client/src/main/java/io/strimzi/kafka/oauth/client/

        //Step4: create credentials for loading the Whispeer by contract address which have been deployed on ETH by step2
        //Hexadecimal strings should not contain spaces or other non-hexadecimal characters.
        //You should trim any leading or trailing spaces from the string before attempting to parse it.
        Credentials credentials = Credentials.create(adminPrivateKey.trim());     

        Whispeer whispeer = Whispeer.load(whispeerContractAddress, web3j, credentials, new DefaultGasProvider());
        // Get Alice's expiration Time after transaction have been mined
        // System.out.println("Alice's expiration time: " + whispeer.getAdmin().send());
        try {
            BigInteger expirationTime = whispeer.getExpirationTime(aliceAddress).send();
            System.out.println("Expiration Time: " + unix2UTC(expirationTime));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    private static void getExpirationTimeWithAdminAddress(Web3j web3j, String whispeerContractAddress, String adminAddress, String aliceAddress) {
        // function getExpirationTime defination 
        /*
         * function getExpirationTime(address user) public view returns (uint) {
         *     if (msg.sender == admin) {
         *         return expirationTime[user];
         *     } else {
         *         return expirationTime[msg.sender];
         *     }
         * }
         * 
         */
        
        Function function = new Function(
                "getExpirationTime",
                Collections.singletonList(new Address(aliceAddress)), // Function parameters
                Collections.singletonList(new org.web3j.abi.TypeReference<org.web3j.abi.datatypes.generated.Uint256>() { })); // Return type

        String encodedFunction = FunctionEncoder.encode(function);
        
        String from = adminAddress;
        String to = whispeerContractAddress;
        String data = encodedFunction;
        Transaction transaction = new Transaction(from, null, null, null, to, null, data, null, null, null);
        EthCall response = null;
        try {
            response = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        List<Type> result = FunctionReturnDecoder.decode(
                response.getValue(),
                function.getOutputParameters());

        if (!result.isEmpty()) {
            BigInteger expirationTime = (BigInteger) result.get(0).getValue();
            System.out.println("Expiration Time: " + unix2UTC(expirationTime));
        }

    }

    private static String unix2UTC(BigInteger timestamp) {
        // Convert the timestamp to an Instant
        Instant instant = Instant.ofEpochSecond(timestamp.longValue());

        // Create a ZonedDateTime in UTC timezone
        ZonedDateTime zonedDateTime = instant.atZone(ZoneId.of("UTC"));

        // Define a date and time format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");

        // Format and print the converted timestamp in UTC
        String utcDateTime = zonedDateTime.format(formatter);
        //System.out.println("UTC DateTime: " + utcDateTime);
        return utcDateTime;
    }
}

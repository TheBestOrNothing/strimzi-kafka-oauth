/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

//import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthFeeHistory;
import org.web3j.protocol.core.methods.response.EthFeeHistory.FeeHistory;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthMaxPriorityFeePerGas;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Type;
import org.web3j.tx.RawTransactionManager;


import org.asynchttpclient.DefaultAsyncHttpClient;
import org.bouncycastle.util.encoders.Hex;
import org.asynchttpclient.AsyncHttpClient;

/**
 * An example consumer implementation
 */
//@SuppressFBWarnings("THROWS_METHOD_THROWS_RUNTIMEEXCEPTION")
public class Web3jWhispeerOauthValidationForAlice {

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
        
        String alicePrivate = properties.getProperty("alicePrivate");
        String whispeerAddress = properties.getProperty("whispeerAddress");
        String alchemy = properties.getProperty("alchemyProvider");

        try {
            Result result = alicePay(alchemy, alicePrivate, whispeerAddress, new BigInteger("1000"));
            if (!result.status) {
                System.out.println("Error happend !!!");
                System.out.println(result.info);
            }

        } catch (Exception e) { 
            e.printStackTrace();
        }
    }

    private static Result alicePay(String provider, String fromPrivate, String to, BigInteger payment) {

        String transHash = null;
        Result result = new Result();
        
        Web3j web3j = Web3j.build(new HttpService(provider));  
        Credentials credentials = Credentials.create(fromPrivate);
        String aliceAddress = credentials.getAddress();
        String from = aliceAddress;
        Whispeer whispeer = Whispeer.load(to, web3j, credentials, new DefaultGasProvider());
        
        BigInteger expirationTime = BigInteger.ZERO;
        try {
            expirationTime = whispeer.getExpirationTime(aliceAddress).send();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            result.status = false;
            result.info = "failied to get expirationTime";
            // Shut down the provider
            web3j.shutdown();
            return result;
        }
        long current = System.currentTimeMillis() / 1000;
        System.out.println("Alice's expiration time: " + expirationTime);
        System.out.println("Current system time: " + current);
        if (expirationTime.longValue() > current) {
            result.status = true;
            result.info = "expirationTime is bigger than current. User is active";
            // Shut down the provider
            web3j.shutdown();
            return result;
        }

        try {

            //Get gasPrice is not using in EIP1559 but used by transaction creation
            EthGasPrice gasPriceResponse = web3j.ethGasPrice().send();
            BigInteger gasPrice = gasPriceResponse.getGasPrice();
            
            //Get ethMaxPriorityFeePerGas
            EthMaxPriorityFeePerGas maxPriorityResponse = web3j.ethMaxPriorityFeePerGas().send();
            BigInteger maxPriorityFeePerGas = maxPriorityResponse.getMaxPriorityFeePerGas();
            
            //Calculate maxFeePerGas, maxFeePerGas = maxPriorityFeePerGas * 1.1
            BigInteger maxFeePerGas = maxPriorityFeePerGas.multiply(BigInteger.valueOf(110)).divide(BigInteger.valueOf(100));
            
            // Get nonce
            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(aliceAddress, DefaultBlockParameterName.PENDING).send();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            
            //Get chainId
            long chainId = web3j.ethChainId().send().getChainId().longValue();
            
            //Get value
            BigInteger payFrequency = whispeer.getPaymentFrequency().send();
            BigInteger monthlyPayment = whispeer.getMonthlyPayment().send();
            BigInteger atLeastPayment = monthlyPayment.multiply(payFrequency);
            
            BigInteger value = BigInteger.ZERO;
            if (atLeastPayment.compareTo(payment) > 0) {
                value = atLeastPayment;
            } else {
                value = payment;
            }
            
            //Get data
            String data = whispeer.pay(atLeastPayment).encodeFunctionCall();
            System.out.println("whispeer.pay(new BigInteger(atLeastPayment): " + data);
            
            // Get gas limit of pay function
            Transaction transaction = new Transaction(from, null, null, null, to, value, data, null, null, null);
            EthEstimateGas estimateGas = web3j.ethEstimateGas(transaction).send();     
            BigInteger gasLimitPay = estimateGas.getAmountUsed();
            System.out.println("gasWhispeerPay estimate the gas amount for pay function: " + gasLimitPay);

            // Update the transaction ready for send to provider
            transaction = new Transaction(from, nonce, gasPrice, gasLimitPay, to, value, data, chainId, maxPriorityFeePerGas, maxFeePerGas);
            
            // Get Alice's expiration Time before transaction send to the alchemy provider
            System.out.println("Alice's expiration time: " + whispeer.getExpirationTime(aliceAddress).send());

            // Sign the transaction and send to the alchemy provider
            RawTransactionManager rawTransactionManager = new RawTransactionManager(web3j, credentials, chainId);

            // Wait for the transaction to be mined
            EthSendTransaction trans = rawTransactionManager.sendEIP1559Transaction(chainId, maxPriorityFeePerGas, maxFeePerGas, gasLimitPay, to, data, value);
            transHash = trans.getTransactionHash();
            System.out.println("https://goerli.etherscan.io/tx/" + transHash);

            boolean isMined = false;
            while (!isMined) {
                EthGetTransactionReceipt transactionReceipt = web3j.ethGetTransactionReceipt(transHash).sendAsync().get();
                Optional<TransactionReceipt> receiptOptional = transactionReceipt.getTransactionReceipt();

                if (receiptOptional.isPresent()) {
                    TransactionReceipt receipt = receiptOptional.get();
                    System.out.println("Transaction Hash2: " + receipt.getTransactionHash());
                    System.out.println("Transaction Status: " + receipt.getStatus());
                    isMined = receipt.isStatusOK();
                    result.status = true;
                    result.info = value.toString() + " have been successfull paied and user is active now";
                    // Other information from the TransactionReceipt
                } else {
                    System.out.println("Transaction receipt not found or still pending.");
                    TimeUnit.SECONDS.sleep(10);
                }
            }
            // Get Alice's expiration Time after transaction have been mined
            System.out.println("Alice's expiration time: " + whispeer.getExpirationTime(aliceAddress).send());

        } catch (Exception e) {
            // Shut down the provider
            web3j.shutdown();
            
            if (transHash == null) {
                result.status = false;
                result.info = "Exception Occure before the transaction construction. " + e.getMessage();
                System.out.println("Exception Occure before the transaction construction");
            } else {
                result.status = false;
                result.info = "https://goerli.etherscan.io/tx/" + transHash;
                System.out.println("Transaction execution failed in mempool, please view in etherscan");
                System.out.println("https://goerli.etherscan.io/tx/" + transHash);
            }
            
            e.printStackTrace();
        }

        // Shut down the provider
        web3j.shutdown();
        return result;
    }

    private static BigInteger getBaseFee(Web3j web3j) {
        // Get the fee history
        EthFeeHistory ethFeeHistory = null;
        try {
            ethFeeHistory = web3j.ethFeeHistory(10, DefaultBlockParameterName.LATEST, null).send();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return BigInteger.ZERO;
        }

        // Get the all fee list in the history
        FeeHistory feeHistory = ethFeeHistory.getFeeHistory();
        List<BigInteger> feeHistoryList = feeHistory.getBaseFeePerGas();
        // Calculate the average using Java streams
        BigInteger averageBaseFee = feeHistoryList.stream()
                .reduce(BigInteger.ZERO, BigInteger::add)
                .divide(BigInteger.valueOf(feeHistoryList.size()));
        return averageBaseFee;        
    }

    private void getGasPriceByHttp(String provider) {
        AsyncHttpClient client = new DefaultAsyncHttpClient();
        try {
            client.prepare("POST", provider)
                .setHeader("accept", "application/json")
                .setHeader("content-type", "application/json")
                .setBody("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\"}")
                .execute()
                .toCompletableFuture()
                .thenAccept(System.out::println)
                .join();

            client.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void getPriorityFeeByHttp(String provider) {
        AsyncHttpClient client = new DefaultAsyncHttpClient();
        try {
            client.prepare("POST", provider)
                .setHeader("accept", "application/json")
                .setHeader("content-type", "application/json")
                .setBody("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_maxPriorityFeePerGas\"}")
                .execute()
                .toCompletableFuture()
                .thenAccept(System.out::println)
                .join();

            client.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    // data: DATA - (optional) Hash of the method signature and encoded parameters. 
    // For details see Ethereum Contract ABI
    // Example: 
    private void getDataByMethodSignature() {
        // Method signature
        String methodSignature = "setPaymentFrequency(uint256)";

        // Encode parameters
        Uint256 value = new Uint256(5); // Replace with your parameter value
        List<Type> inputParameters = Collections.singletonList(value);

        //Get methodId using Keccak-256 hash 
        byte[] methodIdBytes = Hash.sha3(methodSignature.getBytes());
        String methodId = Hex.toHexString(methodIdBytes).substring(0, 8);
        System.out.println("setPaymentFrequency(uint256) methodId: " + methodId);
        // Combine method signature and encoded parameters
        String data = "0x" + FunctionEncoder.encode(methodId, inputParameters);
        System.out.println("setPaymentFrequency(uint256(6)) FunctionEncoder: " + data);
    }
    
    // data: DATA - (optional) Hash of the method signature and encoded parameters. 
    // For details see Ethereum Contract ABI
    // Example: 
    private void getDataByWrapper(Whispeer whispeer) {
        String data = whispeer.setPaymentFrequency(new BigInteger("6")).encodeFunctionCall();
        System.out.println("setPaymentFrequency(uint256(6)) FunctionEncoder: " + data);
    }
    
    private void createTransaction1() {
        String from =  "0xda35443a042b64ED2167F569B5Fe089ca2811aEd";
        String to = "0x7a0acb07cc86206da5c9c2a6d3a718f6d8d0e1a4";
        String data = "0x4f512bc70000000000000000000000000000000000000000000000000000000000000005";
        System.out.println("setPaymentFrequency(uint256(6)) FunctionEncoder: " + data);
        //"gas": "0x709d",
        //"gasprice": "0x59C39F7C",
        //"value": "0x0"
        Transaction transaction1 = new Transaction(from, null, null, null, to, null, data, null, null, null);
    }
    
    private void createTransaction2() {
        String from =  "0xda35443a042b64ED2167F569B5Fe089ca2811aEd";
        String to = "0x7a0acb07cc86206da5c9c2a6d3a718f6d8d0e1a4";
        String data = "0x4f512bc70000000000000000000000000000000000000000000000000000000000000005";
        System.out.println("setPaymentFrequency(uint256(6)) FunctionEncoder: " + data);
        //"gas": "0x709d",
        //"gasprice": "0x59C39F7C",
        //"value": "0x0"
        Transaction transaction2 = Transaction.createEthCallTransaction(from, to, data);
    }
}

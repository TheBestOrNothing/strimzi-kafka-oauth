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
public class Web3jWhispeerPayByAlice {

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
        
        String alchemy = properties.getProperty("alchemyProvider");
        if (alchemy == null) {
            System.out.println("alchemyProvider is null, please adapt the whispeer.properties file");
        }

        String alice = properties.getProperty("aliceAddress");
        String alicePrivate = properties.getProperty("alicePrivate");
        String whispeerAddress = properties.getProperty("whispeerAddress");
        String transHash = null;
        Web3j web3j = null;

        try {
            //Step1: code, compile, unit test, and deployment one smart contract in Remix:

            //Step2: to generate the wrapper code, compile your smart contract:
            // $ solc Whispeer.sol --bin --abi --optimize -o .

            //Step3: then generate the wrapper code using the Web3j CLI:
            // $ web3j generate solidity -b Whispeer.bin  -a Whispeer.abi -o . -p io.strimzi.kafka.oauth.client
            // cp Whispeer.java ~/kafka/whispeer-kafka-oauth/oauth-client/src/main/java/io/strimzi/kafka/oauth/client/

            //Step4: Now you can create and deploy your smart contract:
            web3j = Web3j.build(new HttpService(alchemy));  
            Credentials credentials = Credentials.create(alicePrivate);

            Whispeer whispeer = Whispeer.load(whispeerAddress, web3j, credentials, new DefaultGasProvider());
            /*
             * EIP-1559 transactions require MaxPriorityFeePerGas and MaxFeePerGas values to be considered when picking a network fee:
             * https://goerli.etherscan.io/tx/0xb19adc92871505f07decfda8be0fa70f6fd8c0d4765d646e58fde4b8059d21f8
             * 1. MaxPriorityFeePerGas: A fee to entice a miner to include the transaction.
             * 2. MaxFeePerGas: The highest network fee the user is willing to pay.
             * 3. Only MaxPriorityFeePerGas and MaxFeePerGas be used in EIP-1559 transactions.
             * 4. Gas Price = MaxPriorityFeePerGas + BaseFee, which can been found in etherscan.io
             * 5. BaseFee: A fee that floats based on the network congestion.
             */
            
            /*
             * https://goerli.etherscan.io/tx/0xb19adc92871505f07decfda8be0fa70f6fd8c0d4765d646e58fde4b8059d21f8
             * 1. Transaction Fee = Gas Price * Usage by Txn
             * 2. Gas Price = MaxPriorityFeePerGas + BaseFee
             * 3. Gas Price: Fee Per Gas which not equal Base Fee.
             * 4. Gas Limit: The gas amount fueled for one transaction
             * 5. Gas Limit which can been estimated by EthEstimateGas.getAmountUsed()
             */

            //Get gasPrice is not using in EIP1559 but used by transaction creation
            EthGasPrice gasPriceResponse = web3j.ethGasPrice().send();
            BigInteger gasPrice = gasPriceResponse.getGasPrice();
            
            //Get ethMaxPriorityFeePerGas
            EthMaxPriorityFeePerGas maxPriorityResponse = web3j.ethMaxPriorityFeePerGas().send();
            BigInteger maxPriorityFeePerGas = maxPriorityResponse.getMaxPriorityFeePerGas();
            
            //Calculate maxFeePerGas, maxFeePerGas = maxPriorityFeePerGas * 1.1
            BigInteger maxFeePerGas = maxPriorityFeePerGas.multiply(BigInteger.valueOf(110)).divide(BigInteger.valueOf(100));
            
            // Get nonce
            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(alice, DefaultBlockParameterName.PENDING).send();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            
            //Get chainId
            long chainId = web3j.ethChainId().send().getChainId().longValue();
            
            //Get value
            BigInteger payFrequency = whispeer.getPaymentFrequency().send();
            BigInteger monthlyPayment = whispeer.getMonthlyPayment().send();
            BigInteger atLeastPayment = monthlyPayment.multiply(payFrequency);
            
            //Get data
            String whispeerPayData = whispeer.pay(atLeastPayment).encodeFunctionCall();
            System.out.println("whispeer.pay(new BigInteger(atLeastPayment): " + whispeerPayData);

            String from = alice;
            String to = whispeerAddress;
            String data = whispeerPayData;
            BigInteger value = atLeastPayment;
            
            /*
             * If function is payable in the contract, the value should be assigned in the transaction constructor when estimate gas.
             * https://goerli.etherscan.io/tx/0xd4ce3f7c51bcda13e3f484534b76f2ab9a7c13623ef6c3adf181d8ed84b177d8
             * 
             * The following transaction will cause one error when estimate gas, because the value 1000 is less than atLeastPayment
             * Transaction transaction = new Transaction(from, null, null, null, to, new BigInteger("1000"), data, null, null, null);
             * 
             * The following transaction will be successful when estimate gas because the value equal atLeastPayment
             * Transaction transaction = new Transaction(from, null, null, null, to, atLeastPayment, data, null, null, null);
             */

            /*
             * The gas amount estimated by EthEstimateGas.getAmountUsed() will be same with different transaction construction.
             * 
             * Transaction transaction1 = new Transaction(from, null, null, null, to, value, data, null, null, null);
             * Transaction transaction2 = new new Transaction(from, nonce, gasPrice, gasLimit, to, value, data, chainId, maxPriorityFeePerGas, maxFeePerGas);
             * Transaction transaction3 = new new Transaction(from, null, null, gasLimit, to, value, data, null, maxPriorityFeePerGas, maxFeePerGas);
             * Transaction transaction4 = ......;
             * 
             * So using transaction1 with necessary info is enough to estimate the amount of gas
             */
            
            // Get gas limit of pay function
            Transaction transaction = new Transaction(from, null, null, null, to, value, data, null, null, null);
            EthEstimateGas estimateGas = web3j.ethEstimateGas(transaction).send();     
            BigInteger gasLimitPay = estimateGas.getAmountUsed();
            System.out.println("gasWhispeerPay estimate the gas amount for pay function: " + gasLimitPay);

            // Update the transaction ready for send to provider
            transaction = new Transaction(from, nonce, gasPrice, gasLimitPay, to, value, data, chainId, maxPriorityFeePerGas, maxFeePerGas);
            
            // Get Alice's expiration Time before transaction send to the alchemy provider
            System.out.println("Alice's expiration time: " + whispeer.getExpirationTime(alice).send());

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
                    // Other information from the TransactionReceipt
                } else {
                    System.out.println("Transaction receipt not found or still pending.");
                    TimeUnit.SECONDS.sleep(10);
                }
            }
            // Get Alice's expiration Time after transaction have been mined
            System.out.println("Alice's expiration time: " + whispeer.getExpirationTime(alice).send());
        } catch (Exception e) {
            if (transHash == null) {
                System.out.println("Exception Occure before the transaction construction");
            } else {
                System.out.println("Transaction execution failed in mempool, please view in etherscan");
                System.out.println("https://goerli.etherscan.io/tx/" + transHash);
            }
            
            e.printStackTrace();
        }
        // Shut down the provider
        web3j.shutdown();
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

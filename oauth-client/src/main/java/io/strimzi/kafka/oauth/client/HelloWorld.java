/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.ContractGasProvider;

/**
 * <p>Auto generated code.
 * <p><strong>Do not modify!</strong>
 * <p>Please use the <a href="https://docs.web3j.io/command_line.html">web3j command line tools</a>,
 * or the org.web3j.codegen.SolidityFunctionWrapperGenerator in the 
 * <a href="https://github.com/web3j/web3j/tree/master/codegen">codegen module</a> to update.
 *
 * <p>Generated with web3j version 1.5.0.
 */
@SuppressWarnings("rawtypes")
public class HelloWorld extends Contract {
    public static final String BINARY = "608060405234801561000f575f80fd5b5060408051808201909152600b81526a12195b1b1bc815dbdc9b1960aa1b60208201525f9061003e90826100de565b50610199565b634e487b7160e01b5f52604160045260245ffd5b600181811c9082168061006c57607f821691505b60208210810361008a57634e487b7160e01b5f52602260045260245ffd5b50919050565b601f8211156100d9575f81815260208120601f850160051c810160208610156100b65750805b601f850160051c820191505b818110156100d5578281556001016100c2565b5050505b505050565b81516001600160401b038111156100f7576100f7610044565b61010b816101058454610058565b84610090565b602080601f83116001811461013e575f84156101275750858301515b5f19600386901b1c1916600185901b1785556100d5565b5f85815260208120601f198616915b8281101561016c5788860151825594840194600190910190840161014d565b508582101561018957878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b61034d806101a65f395ff3fe608060405234801561000f575f80fd5b5060043610610034575f3560e01c80635d3a1f9d14610038578063c605f76c1461004d575b5f80fd5b61004b61004636600461010b565b61006b565b005b61005561007c565b6040516100629190610177565b60405180910390f35b5f61007782848361025b565b505050565b60605f805461008a906101d6565b80601f01602080910402602001604051908101604052809291908181526020018280546100b6906101d6565b80156101015780601f106100d857610100808354040283529160200191610101565b820191905f5260205f20905b8154815290600101906020018083116100e457829003601f168201915b5050505050905090565b5f806020838503121561011c575f80fd5b823567ffffffffffffffff80821115610133575f80fd5b818501915085601f830112610146575f80fd5b813581811115610154575f80fd5b866020828501011115610165575f80fd5b60209290920196919550909350505050565b5f6020808352835180828501525f5b818110156101a257858101830151858201604001528201610186565b505f604082860101526040601f19601f8301168501019250505092915050565b634e487b7160e01b5f52604160045260245ffd5b600181811c908216806101ea57607f821691505b60208210810361020857634e487b7160e01b5f52602260045260245ffd5b50919050565b601f821115610077575f81815260208120601f850160051c810160208610156102345750805b601f850160051c820191505b8181101561025357828155600101610240565b505050505050565b67ffffffffffffffff831115610273576102736101c2565b6102878361028183546101d6565b8361020e565b5f601f8411600181146102b8575f85156102a15750838201355b5f19600387901b1c1916600186901b178355610310565b5f83815260209020601f19861690835b828110156102e857868501358255602094850194600190920191016102c8565b5086821015610304575f1960f88860031b161c19848701351681555b505060018560011b0183555b505050505056fea2646970667358221220f9aed1961702023493982bf94347cfe5f8ea18a424ad18cdbdac7dadc7169d2b64736f6c63430008150033";

    public static final String FUNC_HELLOWORLD = "helloWorld";

    public static final String FUNC_SETTEXT = "setText";

    @Deprecated
    protected HelloWorld(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    protected HelloWorld(String contractAddress, Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider);
    }

    @Deprecated
    protected HelloWorld(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    protected HelloWorld(String contractAddress, Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public RemoteFunctionCall<String> helloWorld() {
        final Function function = new Function(FUNC_HELLOWORLD, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Utf8String>() { }));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteFunctionCall<TransactionReceipt> setText(String newText) {
        final Function function = new Function(
                FUNC_SETTEXT, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Utf8String(newText)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    @Deprecated
    public static HelloWorld load(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return new HelloWorld(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    @Deprecated
    public static HelloWorld load(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return new HelloWorld(contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    public static HelloWorld load(String contractAddress, Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider) {
        return new HelloWorld(contractAddress, web3j, credentials, contractGasProvider);
    }

    public static HelloWorld load(String contractAddress, Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        return new HelloWorld(contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public static RemoteCall<HelloWorld> deploy(Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider) {
        return deployRemoteCall(HelloWorld.class, web3j, credentials, contractGasProvider, BINARY, "");
    }

    public static RemoteCall<HelloWorld> deploy(Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        return deployRemoteCall(HelloWorld.class, web3j, transactionManager, contractGasProvider, BINARY, "");
    }

    @Deprecated
    public static RemoteCall<HelloWorld> deploy(Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(HelloWorld.class, web3j, credentials, gasPrice, gasLimit, BINARY, "");
    }

    @Deprecated
    public static RemoteCall<HelloWorld> deploy(Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(HelloWorld.class, web3j, transactionManager, gasPrice, gasLimit, BINARY, "");
    }
}

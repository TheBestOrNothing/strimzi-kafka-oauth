/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

import io.reactivex.Flowable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.BaseEventResponse;
import org.web3j.protocol.core.methods.response.Log;
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
public class Whispeer extends Contract {
    public static final String BINARY = "608060405234801562000010575f80fd5b50604051620010473803806200104783398101604081905262000033916200017a565b5f80546001600160a01b03808a166001600160a01b03199283161790925560018054928916929091169190911790556002620000708682620002ce565b5060036200007f8582620002ce565b5060046200008e8482620002ce565b5060059190915560065550620003969350505050565b6001600160a01b0381168114620000b9575f80fd5b50565b634e487b7160e01b5f52604160045260245ffd5b5f82601f830112620000e0575f80fd5b81516001600160401b0380821115620000fd57620000fd620000bc565b604051601f8301601f19908116603f01168101908282118183101715620001285762000128620000bc565b8160405283815260209250868385880101111562000144575f80fd5b5f91505b8382101562000167578582018301518183018401529082019062000148565b5f93810190920192909252949350505050565b5f805f805f805f60e0888a03121562000191575f80fd5b87516200019e81620000a4565b6020890151909750620001b181620000a4565b60408901519096506001600160401b0380821115620001ce575f80fd5b620001dc8b838c01620000d0565b965060608a0151915080821115620001f2575f80fd5b620002008b838c01620000d0565b955060808a015191508082111562000216575f80fd5b50620002258a828b01620000d0565b93505060a0880151915060c0880151905092959891949750929550565b600181811c908216806200025757607f821691505b6020821081036200027657634e487b7160e01b5f52602260045260245ffd5b50919050565b601f821115620002c9575f81815260208120601f850160051c81016020861015620002a45750805b601f850160051c820191505b81811015620002c557828155600101620002b0565b5050505b505050565b81516001600160401b03811115620002ea57620002ea620000bc565b6200030281620002fb845462000242565b846200027c565b602080601f83116001811462000338575f8415620003205750858301515b5f19600386901b1c1916600185901b178555620002c5565b5f85815260208120601f198616915b82811015620003685788860151825594840194600190910190840162000347565b50858210156200038657878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b610ca380620003a45f395ff3fe6080604052600436106100d9575f3560e01c8063704b6c021161007c57806399858542116100575780639985854214610202578063a223d00b14610223578063be5b02dc14610242578063ee1ef57514610256575f80fd5b8063704b6c02146101b057806387c030ba146101cf5780638efb21a3146101ee575f80fd5b80632dddcf29116100b75780632dddcf291461012d5780633ccfd60b146101415780634f512bc7146101655780636e9960c314610184575f80fd5b806312065fe0146100dd5780631b9265b8146101045780632b5fef2f1461010e575b5f80fd5b3480156100e8575f80fd5b506100f1610275565b6040519081526020015b60405180910390f35b61010c6102ad565b005b348015610119575f80fd5b506100f161012836600461089c565b610395565b348015610138575f80fd5b506006546100f1565b34801561014c575f80fd5b506101556103d8565b60405190151581526020016100fb565b348015610170575f80fd5b5061010c61017f3660046108be565b610477565b34801561018f575f80fd5b506101986104a6565b6040516001600160a01b0390911681526020016100fb565b3480156101bb575f80fd5b5061010c6101ca36600461089c565b6104e0565b3480156101da575f80fd5b5061010c6101e93660046108be565b61052b565b3480156101f9575f80fd5b506005546100f1565b34801561020d575f80fd5b5061021661055a565b6040516100fb9190610918565b34801561022e575f80fd5b5061010c61023d3660046109bd565b6107a6565b34801561024d575f80fd5b50610198610802565b348015610261575f80fd5b5061010c61027036600461089c565b61083b565b5f80546001600160a01b031633146102a85760405162461bcd60e51b815260040161029f90610a50565b60405180910390fd5b504790565b6006546005546102bd9190610a9b565b3410156102de5760405162424a3560e11b815234600482015260240161029f565b335f908152600760205260408120546005549091906102fd9034610ab8565b61030890601f610a9b565b610313906018610a9b565b61031f90610e10610a9b565b90504282111561033a576103338183610ad7565b9150610347565b6103448142610ad7565b91505b335f81815260076020908152604091829020859055815192835234908301527f3d476ad1040b7c53f4279ee863698f162054d1882bf4f671d54cac6d550f4a87910160405180910390a15050565b6001545f906001600160a01b031633036103c457506001600160a01b03165f9081526007602052604090205490565b5050335f9081526007602052604090205490565b5f80546001600160a01b031633146104025760405162461bcd60e51b815260040161029f90610a50565b47801561047057604051339082156108fc029083905f818181858888f1935050505061042f575f91505090565b60408051338152602081018390527fd7a4aa9f3dca5f6606ac15d7e1850920201bbb02c38cd986793779f58ae0dfd3910160405180910390a1600191505090565b5f91505090565b6001546001600160a01b031633146104a15760405162461bcd60e51b815260040161029f90610aea565b600655565b5f80546001600160a01b031633146104d05760405162461bcd60e51b815260040161029f90610a50565b506001546001600160a01b031690565b5f546001600160a01b031633146105095760405162461bcd60e51b815260040161029f90610a50565b600180546001600160a01b0319166001600160a01b0392909216919091179055565b6001546001600160a01b031633146105555760405162461bcd60e51b815260040161029f90610aea565b600555565b61057e60405180606001604052806060815260200160608152602001606081525090565b6001546001600160a01b03163314806105a45750335f9081526007602052604090205442105b6105e55760405162461bcd60e51b815260206004820152601260248201527155736572206973206e6f742061637469766560701b604482015260640161029f565b60026040518060600160405290815f8201805461060190610b17565b80601f016020809104026020016040519081016040528092919081815260200182805461062d90610b17565b80156106785780601f1061064f57610100808354040283529160200191610678565b820191905f5260205f20905b81548152906001019060200180831161065b57829003601f168201915b5050505050815260200160018201805461069190610b17565b80601f01602080910402602001604051908101604052809291908181526020018280546106bd90610b17565b80156107085780601f106106df57610100808354040283529160200191610708565b820191905f5260205f20905b8154815290600101906020018083116106eb57829003601f168201915b5050505050815260200160028201805461072190610b17565b80601f016020809104026020016040519081016040528092919081815260200182805461074d90610b17565b80156107985780601f1061076f57610100808354040283529160200191610798565b820191905f5260205f20905b81548152906001019060200180831161077b57829003601f168201915b505050505081525050905090565b6001546001600160a01b031633146107d05760405162461bcd60e51b815260040161029f90610aea565b60026107dd868883610bb1565b5060036107eb848683610bb1565b5060046107f9828483610bb1565b50505050505050565b5f80546001600160a01b0316331461082c5760405162461bcd60e51b815260040161029f90610a50565b505f546001600160a01b031690565b5f546001600160a01b031633146108645760405162461bcd60e51b815260040161029f90610a50565b5f80546001600160a01b0319166001600160a01b0392909216919091179055565b6001600160a01b0381168114610899575f80fd5b50565b5f602082840312156108ac575f80fd5b81356108b781610885565b9392505050565b5f602082840312156108ce575f80fd5b5035919050565b5f81518084525f5b818110156108f9576020818501810151868301820152016108dd565b505f602082860101526020601f19601f83011685010191505092915050565b602081525f82516060602084015261093360808401826108d5565b90506020840151601f198085840301604086015261095183836108d5565b925060408601519150808584030160608601525061096f82826108d5565b95945050505050565b5f8083601f840112610988575f80fd5b50813567ffffffffffffffff81111561099f575f80fd5b6020830191508360208285010111156109b6575f80fd5b9250929050565b5f805f805f80606087890312156109d2575f80fd5b863567ffffffffffffffff808211156109e9575f80fd5b6109f58a838b01610978565b90985096506020890135915080821115610a0d575f80fd5b610a198a838b01610978565b90965094506040890135915080821115610a31575f80fd5b50610a3e89828a01610978565b979a9699509497509295939492505050565b60208082526019908201527f43616c6c6572206973206e6f74206368616972706572736f6e00000000000000604082015260600190565b634e487b7160e01b5f52601160045260245ffd5b8082028115828204841417610ab257610ab2610a87565b92915050565b5f82610ad257634e487b7160e01b5f52601260045260245ffd5b500490565b80820180821115610ab257610ab2610a87565b60208082526013908201527221b0b63632b91034b9903737ba1030b236b4b760691b604082015260600190565b600181811c90821680610b2b57607f821691505b602082108103610b4957634e487b7160e01b5f52602260045260245ffd5b50919050565b634e487b7160e01b5f52604160045260245ffd5b601f821115610bac575f81815260208120601f850160051c81016020861015610b895750805b601f850160051c820191505b81811015610ba857828155600101610b95565b5050505b505050565b67ffffffffffffffff831115610bc957610bc9610b4f565b610bdd83610bd78354610b17565b83610b63565b5f601f841160018114610c0e575f8515610bf75750838201355b5f19600387901b1c1916600186901b178355610c66565b5f83815260209020601f19861690835b82811015610c3e5786850135825560209485019460019092019101610c1e565b5086821015610c5a575f1960f88860031b161c19848701351681555b505060018560011b0183555b505050505056fea2646970667358221220fc90a533df2dc62052e2966f970cb16fdbf00784fc74ccd18f1b3745773fc1b564736f6c63430008150033";

    public static final String FUNC_GETADMIN = "getAdmin";

    public static final String FUNC_GETBALANCE = "getBalance";

    public static final String FUNC_GETCHAIR = "getChair";

    public static final String FUNC_GETEXPIRATIONTIME = "getExpirationTime";

    public static final String FUNC_GETMONTHLYPAYMENT = "getMonthlyPayment";

    public static final String FUNC_GETPAYMENTFREQUENCY = "getPaymentFrequency";

    public static final String FUNC_GETSOCKET = "getSocket";

    public static final String FUNC_PAY = "pay";

    public static final String FUNC_SETADMIN = "setAdmin";

    public static final String FUNC_SETCHAIR = "setChair";

    public static final String FUNC_SETMONTHLYPAYMENT = "setMonthlyPayment";

    public static final String FUNC_SETPAYMENTFREQUENCY = "setPaymentFrequency";

    public static final String FUNC_SETSOCKET = "setSocket";

    public static final String FUNC_WITHDRAW = "withdraw";

    public static final Event PAYMENTS_EVENT = new Event("Payments", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>() { }, new TypeReference<Uint256>() { }));


    public static final Event WITHDRAWALL_EVENT = new Event("WithdrawAll", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>() { }, new TypeReference<Uint256>() { }));


    @Deprecated
    protected Whispeer(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    protected Whispeer(String contractAddress, Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider);
    }

    @Deprecated
    protected Whispeer(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    protected Whispeer(String contractAddress, Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public static List<PaymentsEventResponse> getPaymentsEvents(TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(PAYMENTS_EVENT, transactionReceipt);
        ArrayList<PaymentsEventResponse> responses = new ArrayList<PaymentsEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            PaymentsEventResponse typedResponse = new PaymentsEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.user = (String) eventValues.getNonIndexedValues().get(0).getValue();
            typedResponse.amount = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static PaymentsEventResponse getPaymentsEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(PAYMENTS_EVENT, log);
        PaymentsEventResponse typedResponse = new PaymentsEventResponse();
        typedResponse.log = log;
        typedResponse.user = (String) eventValues.getNonIndexedValues().get(0).getValue();
        typedResponse.amount = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
        return typedResponse;
    }

    public Flowable<PaymentsEventResponse> paymentsEventFlowable(EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getPaymentsEventFromLog(log));
    }

    public Flowable<PaymentsEventResponse> paymentsEventFlowable(DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(PAYMENTS_EVENT));
        return paymentsEventFlowable(filter);
    }

    public static List<WithdrawAllEventResponse> getWithdrawAllEvents(TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(WITHDRAWALL_EVENT, transactionReceipt);
        ArrayList<WithdrawAllEventResponse> responses = new ArrayList<WithdrawAllEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            WithdrawAllEventResponse typedResponse = new WithdrawAllEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.user = (String) eventValues.getNonIndexedValues().get(0).getValue();
            typedResponse.amount = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static WithdrawAllEventResponse getWithdrawAllEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(WITHDRAWALL_EVENT, log);
        WithdrawAllEventResponse typedResponse = new WithdrawAllEventResponse();
        typedResponse.log = log;
        typedResponse.user = (String) eventValues.getNonIndexedValues().get(0).getValue();
        typedResponse.amount = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
        return typedResponse;
    }

    public Flowable<WithdrawAllEventResponse> withdrawAllEventFlowable(EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getWithdrawAllEventFromLog(log));
    }

    public Flowable<WithdrawAllEventResponse> withdrawAllEventFlowable(DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(WITHDRAWALL_EVENT));
        return withdrawAllEventFlowable(filter);
    }

    public RemoteFunctionCall<String> getAdmin() {
        final Function function = new Function(FUNC_GETADMIN, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Address>() { }));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteFunctionCall<BigInteger> getBalance() {
        final Function function = new Function(FUNC_GETBALANCE, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() { }));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<String> getChair() {
        final Function function = new Function(FUNC_GETCHAIR, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Address>() { }));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteFunctionCall<BigInteger> getExpirationTime(String user) {
        final Function function = new Function(FUNC_GETEXPIRATIONTIME, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, user)), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() { }));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<BigInteger> getMonthlyPayment() {
        final Function function = new Function(FUNC_GETMONTHLYPAYMENT, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() { }));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<BigInteger> getPaymentFrequency() {
        final Function function = new Function(FUNC_GETPAYMENTFREQUENCY, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() { }));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<Socket> getSocket() {
        final Function function = new Function(FUNC_GETSOCKET, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Socket>() { }));
        return executeRemoteCallSingleValueReturn(function, Socket.class);
    }

    public RemoteFunctionCall<TransactionReceipt> pay(BigInteger weiValue) {
        final Function function = new Function(
                FUNC_PAY, 
                Arrays.<Type>asList(), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function, weiValue);
    }

    public RemoteFunctionCall<TransactionReceipt> setAdmin(String newAdmin) {
        final Function function = new Function(
                FUNC_SETADMIN, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, newAdmin)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> setChair(String newChair) {
        final Function function = new Function(
                FUNC_SETCHAIR, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, newChair)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> setMonthlyPayment(BigInteger payment) {
        final Function function = new Function(
                FUNC_SETMONTHLYPAYMENT, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Uint256(payment)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> setPaymentFrequency(BigInteger frequency) {
        final Function function = new Function(
                FUNC_SETPAYMENTFREQUENCY, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Uint256(frequency)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> setSocket(String domain, String ip, String port) {
        final Function function = new Function(
                FUNC_SETSOCKET, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Utf8String(domain), 
                new org.web3j.abi.datatypes.Utf8String(ip), 
                new org.web3j.abi.datatypes.Utf8String(port)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> withdraw() {
        final Function function = new Function(
                FUNC_WITHDRAW, 
                Arrays.<Type>asList(), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    @Deprecated
    public static Whispeer load(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return new Whispeer(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    @Deprecated
    public static Whispeer load(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return new Whispeer(contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    public static Whispeer load(String contractAddress, Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider) {
        return new Whispeer(contractAddress, web3j, credentials, contractGasProvider);
    }

    public static Whispeer load(String contractAddress, Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        return new Whispeer(contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public static RemoteCall<Whispeer> deploy(Web3j web3j, Credentials credentials, ContractGasProvider contractGasProvider, String chairman, String administrator, String domain, String ip, String port, BigInteger monthlyPay, BigInteger payFrequency) {
        String encodedConstructor = FunctionEncoder.encodeConstructor(Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, chairman), 
                new org.web3j.abi.datatypes.Address(160, administrator), 
                new org.web3j.abi.datatypes.Utf8String(domain), 
                new org.web3j.abi.datatypes.Utf8String(ip), 
                new org.web3j.abi.datatypes.Utf8String(port), 
                new org.web3j.abi.datatypes.generated.Uint256(monthlyPay), 
                new org.web3j.abi.datatypes.generated.Uint256(payFrequency)));
        return deployRemoteCall(Whispeer.class, web3j, credentials, contractGasProvider, BINARY, encodedConstructor);
    }

    public static RemoteCall<Whispeer> deploy(Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider, String chairman, String administrator, String domain, String ip, String port, BigInteger monthlyPay, BigInteger payFrequency) {
        String encodedConstructor = FunctionEncoder.encodeConstructor(Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, chairman), 
                new org.web3j.abi.datatypes.Address(160, administrator), 
                new org.web3j.abi.datatypes.Utf8String(domain), 
                new org.web3j.abi.datatypes.Utf8String(ip), 
                new org.web3j.abi.datatypes.Utf8String(port), 
                new org.web3j.abi.datatypes.generated.Uint256(monthlyPay), 
                new org.web3j.abi.datatypes.generated.Uint256(payFrequency)));
        return deployRemoteCall(Whispeer.class, web3j, transactionManager, contractGasProvider, BINARY, encodedConstructor);
    }

    @Deprecated
    public static RemoteCall<Whispeer> deploy(Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit, String chairman, String administrator, String domain, String ip, String port, BigInteger monthlyPay, BigInteger payFrequency) {
        String encodedConstructor = FunctionEncoder.encodeConstructor(Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, chairman), 
                new org.web3j.abi.datatypes.Address(160, administrator), 
                new org.web3j.abi.datatypes.Utf8String(domain), 
                new org.web3j.abi.datatypes.Utf8String(ip), 
                new org.web3j.abi.datatypes.Utf8String(port), 
                new org.web3j.abi.datatypes.generated.Uint256(monthlyPay), 
                new org.web3j.abi.datatypes.generated.Uint256(payFrequency)));
        return deployRemoteCall(Whispeer.class, web3j, credentials, gasPrice, gasLimit, BINARY, encodedConstructor);
    }

    @Deprecated
    public static RemoteCall<Whispeer> deploy(Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit, String chairman, String administrator, String domain, String ip, String port, BigInteger monthlyPay, BigInteger payFrequency) {
        String encodedConstructor = FunctionEncoder.encodeConstructor(Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, chairman), 
                new org.web3j.abi.datatypes.Address(160, administrator), 
                new org.web3j.abi.datatypes.Utf8String(domain), 
                new org.web3j.abi.datatypes.Utf8String(ip), 
                new org.web3j.abi.datatypes.Utf8String(port), 
                new org.web3j.abi.datatypes.generated.Uint256(monthlyPay), 
                new org.web3j.abi.datatypes.generated.Uint256(payFrequency)));
        return deployRemoteCall(Whispeer.class, web3j, transactionManager, gasPrice, gasLimit, BINARY, encodedConstructor);
    }

    public static class Socket extends DynamicStruct {
        public String domainName;

        public String ipAddress;

        public String portNumber;

        public Socket(String domainName, String ipAddress, String portNumber) {
            super(new org.web3j.abi.datatypes.Utf8String(domainName), 
                    new org.web3j.abi.datatypes.Utf8String(ipAddress), 
                    new org.web3j.abi.datatypes.Utf8String(portNumber));
            this.domainName = domainName;
            this.ipAddress = ipAddress;
            this.portNumber = portNumber;
        }

        public Socket(Utf8String domainName, Utf8String ipAddress, Utf8String portNumber) {
            super(domainName, ipAddress, portNumber);
            this.domainName = domainName.getValue();
            this.ipAddress = ipAddress.getValue();
            this.portNumber = portNumber.getValue();
        }
    }

    public static class PaymentsEventResponse extends BaseEventResponse {
        public String user;

        public BigInteger amount;
    }

    public static class WithdrawAllEventResponse extends BaseEventResponse {
        public String user;

        public BigInteger amount;
    }
}

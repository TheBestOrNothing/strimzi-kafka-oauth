// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

contract Whispeer {
    // chairperson who is in charge of this business and have right to withdraw the income
    address payable private chairperson;

    // admin who have right to set value of properties in the contract
    address private admin;

    // Define a structure named Socket
    struct Socket {
        // the server's domain name which can map to ip address
        string domainName;
        // if the domian name have been set, please ignore the ipaddress
        // otherwise using the ip address to connect the kafka server
        string ipAddress;
        // A socket is a combination of an IP address and a port number, 
        // and it represents a communication endpoint.
        string portNumber;
    }

    // Declare a state variable of the Socket structure
    Socket private socket;

    // monthlyPayment means one user should pay for at least one month
    uint private monthlyPayment;
    // How many month should be paied each time
    uint private paymentFrequency;

    // The expiration date for each user
    mapping(address => uint) private expirationTime;

    // Events that will be emitted on changes.
    event WithdrawAll(address user, uint amount);
    event Payments(address user, uint amount);

    // Less than minium payment.
    error LessThanMiniumPayment(uint amount);

    modifier isChair() {
        // If the first argument of 'require' evaluates to 'false', execution terminates and all
        // changes to the state and to Ether balances are reverted.
        // This used to consume all gas in old EVM versions, but not anymore.
        // It is often a good idea to use 'require' to check if functions are called correctly.
        // As a second argument, you can also provide an explanation about what went wrong.
        require(msg.sender == chairperson, "Caller is not chairperson");
        _;
    }

    modifier isAdmin() {
        require(msg.sender == admin, "Caller is not admin");
        _;
    }

    modifier isActiveUser() {
        require(msg.sender == admin || expirationTime[msg.sender] > block.timestamp, "User is not active");
        _;
    }

    /// Create a whispeer with `monthlyPayment` and `paymentFrequency`
    /// on behalf of the chairperson `chairpersonAddress`.
    //
    constructor(
        address payable chairman,
        address administrator,
        string memory domain,
        string memory ip,
        string memory port,
        uint monthlyPay,
        uint payFrequency
 
    ) {
        chairperson = chairman;
        admin = administrator;
        socket.domainName = domain;
        socket.ipAddress = ip;
        socket.portNumber = port;
        monthlyPayment = monthlyPay;
        paymentFrequency = payFrequency;
    }

    /// The value sent together with the transaction.
    /// The value will only be refunded if the
    /// value less than miniPayment.
    function pay() external payable {
        // No arguments are necessary, all
        // information is already part of
        // the transaction. The keyword payable
        // is required for the function to
        // be able to receive Ether.

        // If the vaule is less than miniPayment, 
        // send the money back (the revert statement
        // will revert all changes in this
        // function execution including
        // it having received the money).
        if (msg.value < monthlyPayment * paymentFrequency)
            revert LessThanMiniumPayment(msg.value);

        uint senderDueTime = expirationTime[msg.sender];

        // msg.value (uint): number of wei sent with the message
        // so the monthlyPayment should be measured in wei
        // 31 days per month to make service due as long as possible
        uint duration = msg.value/monthlyPayment * 31 * 24 * 3600;

        if(senderDueTime > block.timestamp){
            senderDueTime += duration;
        } else {
            senderDueTime = block.timestamp + duration;
        }

        expirationTime[msg.sender] = senderDueTime;

        emit Payments(msg.sender, msg.value);
    }

    // To set chair
    function setChair(address payable newChair) external isChair{
        chairperson = newChair;
    }

    // To get chair
    function getChair() external isChair view returns (address){
        return chairperson;
    }

    // To set admin
    function setAdmin(address newAdmin) external isChair{
        admin = newAdmin;
    }

    // To get admin
    function getAdmin() external isChair view returns (address){
        return admin;
    }

    // To set socket
    function setSocket(string calldata domain, string calldata ip, string calldata port) external isAdmin{
        socket.domainName = domain;
        socket.ipAddress = ip;
        socket.portNumber = port;
    }

    // To get socket
    function getSocket() external isActiveUser view returns (Socket memory){
        return socket;
    }

    // To set monthly  payment
    function setMonthlyPayment(uint payment) external isAdmin{
        monthlyPayment = payment;
    }

    // To get monthly  payment
    function getMonthlyPayment() public view returns (uint){
        return monthlyPayment;
    }

    // To set payment frequency;
    // How many month should be paied each time
    function setPaymentFrequency(uint frequency) external isAdmin{
        paymentFrequency = frequency;
    }

    // To get payment frequency;
    function getPaymentFrequency() public view returns (uint){
        return paymentFrequency;
    }

    // To get user's expirationDate by user or admin
    function getExpirationTime(address user) public view returns (uint) {
        if (msg.sender == admin) {
            return expirationTime[user];
        } else {
            return expirationTime[msg.sender];
        }
    }

    // How many Balance can be withdrawed of this contract.
    function getBalance() external isChair view returns (uint) {
        
        uint amount = address(this).balance;
        return amount;
    }

    // Withdraw all the benefit and balance from the contract.
    function withdraw() external isChair returns (bool) {
        
        uint amount = address(this).balance;
        if (amount > 0) {
            // msg.sender is not of type `address payable` and must be
            // explicitly converted using `payable(msg.sender)` in order
            // use the member function `send()`.
            if (!payable(msg.sender).send(amount)) {
                // No need to call throw here, just reset the amount owing
                return false;
            }
            emit WithdrawAll(msg.sender, amount);
            return true;
        }
        return false;
    }
}

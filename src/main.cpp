#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <random>

#include <hash.hpp>

// Block structure
struct Block {
    int blockNumber;
    std::string previousHash;
    std::time_t timestamp;
    std::vector<std::string> transactions;
    std::string hash;
};

// Validator structure
struct Validator {
    std::string publicKey;
    int stake;
};

// Blockchain class
class Blockchain {
private:
    std::vector<Block> chain;
    std::vector<Validator> validators;

public:
    Blockchain() {
        // Initialize blockchain with genesis block
        Block genesisBlock;
        genesisBlock.blockNumber = 0;
        genesisBlock.previousHash = "0";
        genesisBlock.timestamp = std::time(nullptr);
        genesisBlock.transactions.push_back("Genesis transaction");
        genesisBlock.hash = calculateHash(genesisBlock);

        chain.push_back(genesisBlock);
    }

    std::string calculateHash(Block& block) {
        // Initialize block header data
        std::string headerData = std::to_string(block.blockNumber) + block.previousHash + std::to_string(block.timestamp);

        // Concatenate transaction data
        for (const std::string& transaction : block.transactions) {
            headerData += transaction;
        }

        // Implement hash calculation
        return sha256(headerData);
    }

    void addBlock(Block& block) {
        // Validate the block and add it to the chain
        if (isValidBlock(block)) {
            chain.push_back(block);
        }
        else {
            std::cout << "Invalid block. Cannot add to the chain." << std::endl;
        }
    }

    bool isValidBlock(Block& block) {
        // Implement validation rules
        const Block& lastBlock = getLastBlock();

        // Check if the previous hash matches the hash of the last block
        if (block.previousHash != lastBlock.hash) {
            return false;
        }

        // Check block number is one more than the last block
        if (block.blockNumber != lastBlock.blockNumber + 1) {
            return false;
        }

        // Check if the timestamp is in the past
        std::time_t currentTime = std::time(nullptr);
        if (block.timestamp > currentTime) {
            return false;
        }

        // Check for correct hash value
        std::string calculatedHash = calculateHash(block);
        if (block.hash != calculatedHash) {
            return false;
        }

        return true;
    }

    const Block& getLastBlock() const {
        return chain.back();
    }

    // Proof of Stake (PoS) related functions

    void addValidator(Validator& validator) {
        // Add a new validator to the network
        if (isValidValidator(validator)) {
            validators.push_back(validator);
        }
    }

    bool isValidValidator(const Validator& validator) {
        // Check if the validator is valid

        // Check if the validator is already in the network
        for (const Validator& v : validators) {
            if (v.publicKey == validator.publicKey) {
                return false;
            }
        }

        // Check if the validator has enough stake
        if (validator.stake <= 0) {
            return false;
        }

        return true;
    }

    const Validator& selectValidator() const {
        // Randomly select a validator based on their stake

        // Calculate the total stake
        int totalStake = 0;
        for (const Validator& validator : validators) {
            totalStake += validator.stake;
        }

        // Generate a random number between 0 and totalStake
        std::random_device rd;
        int randomNumber = rd() % totalStake + 1;

        std::cout << "Random number: " << randomNumber << std::endl;

        // Select the validator based on the random number
        int stakeSum = 0;
        for (const Validator& validator : validators) {
            stakeSum += validator.stake;
            if (stakeSum >= randomNumber) {
                // Validator selected
                return validator;
            }
        }

        // Throw an error if no validator is selected
        throw std::runtime_error("No validator selected");
    }

    void validateBlock(Block& block) {
        // Validate the block using PoS consensus rules

        // Select a validator
        const Validator& validator = selectValidator();

        // Check if the validator is valid
        if (!isValidValidator(validator)) {
            std::cout << "Invalid validator" << std::endl;
            return;
        }

        // Additional checks and validation rules...

        // Block is valid, add it to the chain
        chain.push_back(block);
    }
};

int main() {
    // Create a new blockchain instance
    Blockchain blockchain;

    // Output the genesis block
    const Block& genesisBlock = blockchain.getLastBlock();
    std::cout << "Genesis block: " << genesisBlock.hash << std::endl;

    // Create a new block
    Block newBlock;
    newBlock.blockNumber = 1;
    newBlock.previousHash = genesisBlock.hash;
    newBlock.timestamp = std::time(nullptr);
    newBlock.transactions.push_back("Transaction 1");
    newBlock.transactions.push_back("Transaction 2");
    newBlock.hash = blockchain.calculateHash(newBlock);

    // Add the new block to the chain
    blockchain.addBlock(newBlock);

    // Output the new block
    const Block& lastBlock = blockchain.getLastBlock();
    std::cout << "Block " << lastBlock.blockNumber << ": " << lastBlock.hash << std::endl;

    // Create a new validator
    Validator validator;
    validator.publicKey = "publicKey";
    validator.stake = 100;

    // Add the validator to the network
    blockchain.addValidator(validator);

    // Create a second validator
    Validator validator2;
    validator2.publicKey = "publicKey2";
    validator2.stake = 200;

    // Add the second validator to the network
    blockchain.addValidator(validator2);

    // Select a validator
    const Validator& selectedValidator = blockchain.selectValidator();

    // Output the selected validator
    std::cout << "Selected validator: " << selectedValidator.publicKey << std::endl;

    return 0;
}

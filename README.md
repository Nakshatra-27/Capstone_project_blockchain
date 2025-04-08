# Capstone_project_blockchain
## Secure Communication System using Blockchain and End-to-End Encryption

This project implements a *secure, tamper-resistant, and decentralized communication system* that uses *Blockchain* to log messages and *End-to-End Encryption (E2EE)* to keep them private. The goal is to build a lightweight proof-of-concept that ensures:

- 🔒 Only the sender and receiver can read the messages.
- 📦 Every message is stored securely in a blockchain.
- 🔁 Messages cannot be modified without detection (integrity check).


## 🧠 Introduction

*Blockchain* is a secure, distributed digital ledger system where data is stored in blocks connected like a chain. Each block contains a unique hash and a reference to the previous block, making it nearly impossible to tamper with the data without detection.

*End-to-End Encryption (E2EE)* ensures that only the communicating users can read the messages. Even if a third party intercepts the data, they won't be able to decrypt it.

Combining these two technologies creates a powerful communication platform where *privacy, trust, and transparency* are built-in.


## 🎯 Objectives

- Implement a basic end-to-end encrypted message handler using Fernet.
- Store all encrypted messages inside a tamper-proof blockchain.
- Link all blocks using SHA256 hash chains for message integrity.
- Simulate sender and receiver environments where only intended users can decrypt messages.

## 🛠️ Methodology

The system is built using Python and is divided into three core components:

1. *Block Class*:
   - Represents each message block.
   - Contains encrypted data, timestamp, current and previous hash.

2. *Blockchain Class*:
   - Starts with a genesis block.
   - Adds new encrypted messages as blocks.
   - Maintains the hash chain using SHA256.

3. *MessageHandler Class*:
   - Uses Fernet for symmetric encryption.
   - Handles key generation, encryption, decryption, and integrity checks.
   - Verifies message authenticity with hashing.

4. *Main Program*:
   - Accepts message input from user.
   - Encrypts, stores, and allows later decryption by receiver.
   - Simulates multi-user message passing.

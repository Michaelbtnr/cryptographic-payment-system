# Secure Payment System

This project was developed as a final project for the "Information Security and Cryptology" course.  
It simulates the encryption, signing, verification, and decryption flow of a credit card transaction in a secure payment system.

## Overview

The system uses a hybrid cryptographic design:
- **Salsa20** for symmetric encryption of transaction data
- **EC-ElGamal** for secure encryption of the Salsa20 session key
- **Lamport One-Time Signatures (OTS)** for digital signatures
- **Merkle Tree** for scalable authentication over multiple Lamport key pairs

* The algorithms were not implemented from scratch in this project. Instead, the project integrates and builds upon existing reference implementations from publicly available GitHub repositories.

The goal of the project is to demonstrate how different cryptographic mechanisms can be combined to provide confidentiality, integrity, authenticity, and key protection in a payment-related scenario.

While the required part of the project focused on the core cryptographic algorithms, the Merkle Tree mechanism was integrated as an additional enhancement beyond the requirements.
This extension was especially well received during the project presentation, as it reflected a level of design initiative and cryptographic depth.

## Repository Structure
- `ecc/` – eliptic curve EL-Gamal implemantation
- `salsa20/` – salsa20 implemantation
- `merkle_tree_master/` – Merkle Tree + Lamport OTS implementation

* `protocol.py` contains both client-side and server-side functions, as required by the project specification for the simulation.
* This structure was chosen for the purpose of demonstrating the flow in a single implementation file.
* It does not reflect a production-oriented separation between client and server components.

## How to Run

1. Clone the repository
2. Install the required dependencies. make sure "hashlib" & "secrets" libraries are installed
3. Run secure_payment_main.py
5. Follow the demo flow for authentication, encryption, verification, and decryption

## Authentication Concept

Before sending a transaction, the client proves its identity using a Lamport private key associated with a Merkle tree structure.  
This allows the server to verify that the client is the legitimate owner of the registered Merkle root.

In other words, even if an attacker knows the client’s identity, they still cannot authenticate successfully without the corresponding secret Lamport key material.

## Transaction Flow

### 1. Authentication
The client proves ownership of its registered Merkle root by signing the required authentication data with its Lamport private key.

### 2. Preparation
1. The client generates a Lamport key pair.
2. The client initiates a transaction request.
3. The server generates an EC-ElGamal key pair and sends the public key to the client.

### 3. Encryption and Signing
1. The client generates a random 256-bit Salsa20 session key `Ks`.
2. The client encrypts the transaction message using Salsa20:
   `C = Salsa20(Ks, nonce, message)`
3. The client encrypts `Ks` using the server's EC-ElGamal public key.
4. The client computes a digest over the encrypted data.
5. The client signs the digest using Lamport OTS.
6. The client sends the ciphertext, encrypted session key, and signature to the server.

### 4. Verification and Decryption
1. The server verifies the Lamport signature.
2. The server decrypts the Salsa20 session key using EC-ElGamal.
3. The server decrypts the ciphertext using Salsa20.
4. The server processes the transaction and returns a confirmation.

## Why These Components?

- **Salsa20** provides fast symmetric encryption for the transaction payload.
- **EC-ElGamal** protects the session key during transfer.
- **Lamport OTS** provides hash-based digital signatures.
- **Merkle Tree** solves the one-time limitation of Lamport signatures by allowing many one-time keys to be managed under one public root.

## Notes

- Reusing the same key and nonce in Salsa20 is insecure.
- Lamport signatures are one-time signatures and must not be reused.
- This project is an academic prototype and demonstration, not a production-ready payment system.

## Disclaimer

This repository was created for academic and educational purposes only.
It is intended to demonstrate cryptographic design concepts and secure transaction flow simulation.

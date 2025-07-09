# PIPE: Identity-Aware Privacy-Enhanced Source and Path Verification for Strengthened Network Accountability

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PIPE is a novel network security architecture that integrates Decentralized Identity (DID) with source and path verification. It enhances network-layer accountability and privacy by securely binding user identity, address, path, and data, addressing the fundamental trade-offs between security and privacy in the current Internet architecture.

---

## 📝 Abstract

Network-layer security threats have become increasingly sophisticated, exposing significant vulnerabilities in the current Internet architecture. Despite various proposed solutions, the field faces fundamental challenges in balancing user privacy with network security and achieving practical deployment. This paper presents a novel approach called PIPE (Privacy-preserving Identity and Path Enhancement), which leverages a distributed infrastructure of Key Distribution Servers (KDS) to integrate Decentralized Identity (DID) with source and path verification. Our solution binds user identity, address, path, and data while maintaining privacy through encryption and per-hop address transformation. By embedding DID information in address tags and implementing encrypted path verification, we achieve enhanced network accountability without compromising privacy. Experimental results demonstrate PIPE's practicality and advantages over existing approaches in terms of deployment flexibility and security guarantees. Our work contributes to the evolution of secure network architectures by balancing accountability requirements with privacy protection while ensuring practical deployability.

---

## ✨ Key Features

* **Integrated Identity, Source, and Path Verification**: PIPE is the first mechanism to bind DIDs to the network layer, achieving a triple verification of user identity, source address, and packet path.
* **Strong Privacy Guarantees**: Implements an innovative encryption scheme that provides:
    * **Sender Identity Anonymity**: Conceals the sender's true identity from unauthorized parties.
    * **Source Address Privacy**: Transforms source address tags at every hop to prevent traffic analysis.
    * **Path Privacy**: Encrypts path information, ensuring forwarding nodes only know their immediate neighbors.
    * **Sender-Receiver Unlinkability**: Prevents observers from linking traffic flows between senders and receivers.
* **Enhanced Accountability**: Enables authorized network providers to trace malicious activity back to a verifiable identity, striking a balance between user privacy and network security management.
* **High Performance & Deployability**:
    * Designed as an IPv6 compliant extension header, ensuring seamless integration with existing network infrastructure.
    * Demonstrates line-rate packet processing on programmable hardware (Intel Tofino 2) with negligible performance overhead (1-6 µs additional end-to-end latency).
    * Requires no asymmetric cryptography in the data plane, optimizing for forwarding efficiency.

---

## 🏗️ Architecture Overview

PIPE's architecture consists of four main components that work together to provide a secure and private communication framework.

1.  **End Hosts (Source/Destination)**: The originators and consumers of traffic. The Source host initiates the security process by requesting keys from the KDS, encrypting path information, and embedding identity tags into packets. The Destination verifies the integrity and authenticity of received packets.
2.  **Intermediate Routers**: Forward packets while participating in the verification process. Each router performs a lightweight, symmetric-key cryptographic operation to update the packet's verification and identity tags before forwarding it to the next hop.
3.  **Key Distribution Servers (KDS)**: Trusted entities within each Autonomous System (AS) that form a distributed trust infrastructure. They are responsible for managing and distributing cryptographic keys, generating Anonymous Identifiers (AIDs) from DIDs, and defining the secure path for packets.
4.  **Blockchain Infrastructure**: An optional distributed ledger that can serve as an immutable and decentralized root of trust for identity attestations (DIDs).

## 📜 Citation
If you use PIPE in your research, please cite our paper:

```
@inproceedings{
  title={{PIPE: Identity-Aware Privacy-Enhanced Source and Path Verification for Strengthened Network Accountability}},
  year={2025}
}
```
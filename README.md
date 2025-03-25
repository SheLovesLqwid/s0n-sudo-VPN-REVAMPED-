
# Self-made-VPN

This repository is a **self-made VPN** that provides a highly customizable and robust VPN solution using advanced techniques. The original concept and implementation were created by **[S0n-sudo](https://github.com/S0n-sudo)**. I have revamped the project by adding several new features, improving existing ones, and optimizing the overall structure to provide an even more robust VPN solution. This detailed README includes a breakdown of the original features, the new enhancements, installation instructions, usage, and more.

## Table of Contents

- [Overview](#overview)
- [Original Creator](#original-creator)
- [Features](#features)
  - [Original Features by S0n-sudo](#original-features-by-son-sudo)
  - [New Features Added](#new-features-added)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Running the VPN](#running-the-vpn)
  - [Connecting and Disconnecting](#connecting-and-disconnecting)
- [Security](#security)
- [Proxy Integration](#proxy-integration)
- [Encryptions and Security Protocols](#encryptions-and-security-protocols)
- [Contributing](#contributing)
- [License](#license)

## Overview

This self-made VPN allows you to connect to the internet securely, privately, and anonymously. By utilizing a combination of encryption, proxy servers, and dynamic key management, it ensures that your online activities remain protected from surveillance and potential attacks. The project includes various tools to make the VPN setup as flexible and efficient as possible.

This project includes advanced features such as:

- **Advanced Proxy Pooling**
- **AES and Kyber-1024 encryption**
- **Key hiding via steganography**
- **Password-based authentication and entropy-based key derivation**
- **Support for dynamic proxy management and refresh rates**
- **Automatic reconnection and error handling mechanisms**

The code is designed to be modular and configurable, allowing you to choose your preferred security and privacy features.

## Original Creator

This project was initially created by **[S0n-sudo](https://github.com/S0n-sudo)**, who designed and implemented the core components of the VPN system. All original code, ideas, and contributions are attributed to him.

I, [Your Name], have taken the project forward by adding new features, improving performance, and enhancing the documentation.

## Features

### Original Features by S0n-sudo

The following features were present in the original implementation created by **S0n-sudo**:

1. **Custom VPN Setup**: The original VPN setup included the creation of custom VPN configurations, encryption keys, and tunnel management, making it a flexible and customizable solution.
2. **Proxy Support**: Proxy support was integrated to allow the VPN to work seamlessly with multiple proxy providers.
3. **Dynamic Key Generation**: Key pairs and public/private keys were generated dynamically, ensuring a high level of security.
4. **Automatic Key Management**: Keys were automatically managed and rotated to ensure ongoing security and prevent key leakage.
5. **Basic Encryption**: The system used simple encryption schemes (AES, RSA) to secure traffic.

### New Features Added

The following features have been added to enhance the original system:

1. **Advanced Proxy Pool Management**:
   - Proxy sources are dynamically updated and rotated based on performance and availability.
   - **Custom Proxy Sources**: Additional proxy sources have been added for greater redundancy and anonymity.
   - **Proxy Validation**: Proxies are tested for functionality before being added to the pool.
   - **Proxy Anonymity Level**: Proxies are filtered based on their anonymity level to ensure secure connections.
   
2. **Enhanced Encryption and Key Derivation**:
   - **AES-GCM Encryption** for securing VPN traffic, providing authenticated encryption with additional security.
   - **Kyber-1024 Post-Quantum Cryptography**: Integration of Kyber-1024 for post-quantum secure key encapsulation and exchange.
   - **Argon2 Key Derivation**: Password-based key derivation using the Argon2 algorithm to protect against brute-force attacks.
   - **HMAC-based Integrity Check**: Additional HMAC checks for ensuring the integrity of encrypted data.

3. **Steganographic Key Hiding**:
   - The private key is hidden within an image using **LSB Steganography**, adding an additional layer of security.

4. **Automatic Reconnection and Proxy Switching**:
   - Automatic reconnection and switching between proxies when a connection is lost or a proxy becomes unavailable.

5. **Key Rotation and Refreshing**:
   - Dynamic key rotation with entropy-based generation methods to ensure ongoing security.
   - Automatic refresh of keys and proxies to maintain secure connections.

6. **Improved Logging and Error Handling**:
   - Enhanced logging capabilities to track VPN activity, proxy status, and encryption details.
   - Error handling for better detection and reporting of potential issues during VPN operations.

7. **Proxy Encryption**:
   - **Proxy Encryption**: Added support for encrypting proxy data with AES and HMAC to further secure connections.
   - **Decryption**: Support for securely decrypting and verifying proxy settings before use.

8. **Additional Security Features**:
   - Integration of entropy-based key derivation to enhance the randomness and strength of encryption keys.
   - Support for different types of proxies (HTTP, SOCKS5) to provide flexibility in VPN setup.

9. **Full Documentation**:
   - Comprehensive documentation, including setup guides, installation instructions, and detailed explanations of each feature.
   - **Security Best Practices** have been integrated into the documentation to help users secure their VPN connections effectively.

## Getting Started

### Prerequisites

Before you can use the VPN system, you need to have the following dependencies installed:

- **Python 3.7+**
- **pip** (Python package manager)
- **cryptography** library for encryption
- **aiohttp** library for asynchronous HTTP requests
- **requests** library for HTTP operations
- **beautifulsoup4** for parsing HTML data
- **stegano** for steganographic key hiding

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/S0n-sudo/Self-made-VPN.git
   cd Self-made-VPN
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up any necessary environment variables. For example, you may want to specify a password or other configurations:
   ```bash
   export IP_CHANGER_PASS="YourSuperComplexPassword"
   ```

4. Ensure you have the base image (for key hiding) and the required proxy sources.

### Configuration

- Modify the configuration files to suit your needs, including setting up the proxy sources and desired encryption protocols.
- Ensure you have the necessary keys stored in the specified locations (such as the `KEY_FILE` and `PUBLIC_KEY_FILE`).
- You can also adjust the `REFRESH_INTERVAL`, `MAX_ASYNC_TASKS`, and other settings for optimal performance.

## Usage

### Running the VPN

To start the VPN, simply run the following command:

```bash
python vpn_script.py
```

This will initiate the VPN connection, select an appropriate proxy, and establish an encrypted tunnel.

### Connecting and Disconnecting

Once connected, the VPN will automatically manage your connection, proxy switches, and reconnections if the connection drops. To disconnect the VPN, you can manually terminate the script or use any custom shutdown procedures implemented.

## Security

The self-made VPN uses a combination of strong encryption, key management, and anonymity mechanisms to ensure the privacy and security of your connection. Some of the key security features include:

- AES-GCM encryption for traffic
- Kyber-1024 post-quantum secure key encapsulation
- Password-based key derivation with Argon2
- Proxy rotation and validation
- Steganographic key hiding

### Encryptions and Security Protocols

The system uses the following encryption techniques:

- **AES-GCM** for authenticated encryption of data.
- **Kyber-1024** post-quantum key exchange algorithm.
- **HMAC** for integrity checks.
- **Argon2** for password-based key derivation.
- **LSB Steganography** for hiding the private key in an image.

## Proxy Integration

The VPN integrates with various proxy providers to ensure that users can route their traffic through anonymous proxies. Proxies are dynamically managed, validated, and rotated to maintain a high level of privacy.

- **Dynamic Proxy Pool**: Proxies are regularly refreshed based on availability.
- **Proxy Anonymity Level Filtering**: Proxies are filtered based on their anonymity level (elite, anonymous).
- **Proxy Testing**: Proxies are tested before being used in the VPN tunnel.

---

## Contributing

If you would like to contribute to this project, please fork the repository, make your changes, and submit a pull request. Ensure your code is well-documented, follows best practices, and passes all tests.

---


## Special Thanks

A huge **thank you** to **[S0n-sudo](https://github.com/S0n-sudo)** for creating the original VPN project. His work truly opened my eyes to the power of building a self-made VPN, and I can't believe I didn't think about it sooner. The code here is based entirely on his original implementation. All I did was revamp and add new features to enhance it. Please make sure to check out and give credit to the original creator for the core work — none of this would be possible without his vision.

---

# Go Playground

A collection of Go implementations for common algorithms, data structures, and system design patterns. This repository serves as both a learning resource and a reference implementation for various programming concepts.

## Submodules

### [Encryption](encryption/README.md)
A flexible and secure text encryption library with configurable ciphers, IV generation, serialization formats, and key rotation. Features AES-256-GCM encryption, Rails ActiveRecord compatibility, and PBKDF2 key derivation.

### Consistent Hashing
A robust implementation of consistent hashing for distributed systems and load balancing. Provides minimal redistribution when nodes are added/removed, virtual node support, and configurable replication.

## Getting Started

Each submodule is a standalone Go package that can be used independently. To use a submodule:

```bash
# Clone the repository
git clone https://github.com/kikihakiem/playground.git

# Navigate to the desired submodule
cd playground/<submodule-name>

# Install dependencies
go mod download
```

## Contributing

Contributions are welcome! Each submodule has its own contribution guidelines. Please refer to the specific submodule's README for details.

## License

This project is licensed under the MIT License.

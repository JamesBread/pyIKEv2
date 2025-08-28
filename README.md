# pyIKEv2

A complete Python3 implementation of IKEv2 (Internet Key Exchange Protocol Version 2) that fully complies with RFC 7296.

## Features

- **Full RFC 7296 Compliance**: Complete implementation of IKEv2 protocol
- **Comprehensive Cryptographic Support**: 
  - Encryption: AES-CBC, AES-CTR, AES-GCM, 3DES, ChaCha20-Poly1305
  - Integrity: HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, AES-XCBC
  - PRF: HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
  - DH Groups: MODP (2048-8192), ECP (256/384/521), Curve25519, Curve448
- **State Machine**: Proper IKEv2 state handling with support for all exchange types
- **NAT Traversal**: Built-in NAT-T support on port 4500
- **Configuration Management**: YAML/JSON based configuration
- **CLI Interface**: Comprehensive command-line tools for management
- **Extensible Architecture**: Modular design for easy extension

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from source

```bash
git clone https://github.com/yourusername/pyikev2.git
cd pyikev2
pip install -r requirements.txt
python setup.py install
```

### Install via pip

```bash
pip install pyikev2
```

## Quick Start

### 1. Generate a sample configuration

```bash
pyikev2 config --generate -o /etc/pyikev2/config.yaml
```

### 2. Edit the configuration

```yaml
daemon:
  local_addresses: ['0.0.0.0']
  local_port: 500
  nat_port: 4500
  log_level: INFO

crypto:
  proposals:
    - encryption:
        - algorithm: aes256-gcm
          key_length: 256
      integrity: ['none']
      prf: ['hmac-sha256']
      dh_group: ['curve25519', 'ecp256']

connections:
  site-to-site:
    type: tunnel
    auth_method: psk
    psk: 'your-pre-shared-key'
    local:
      id: 'local@example.com'
      subnet: '10.1.0.0/16'
    remote:
      id: 'remote@example.com'
      subnet: '10.2.0.0/16'
```

### 3. Start the daemon

```bash
# Start in foreground
pyikev2 start -c /etc/pyikev2/config.yaml

# Start as daemon
pyikev2 start -c /etc/pyikev2/config.yaml --daemon
```

### 4. Initiate a connection

```bash
pyikev2 connect 203.0.113.1 -p 500
```

## Usage

### Command Line Interface

```bash
# Start/stop daemon
pyikev2 start [-c CONFIG] [--daemon]
pyikev2 stop
pyikev2 status

# Connection management
pyikev2 connect PEER_IP [-p PORT]
pyikev2 list

# Configuration
pyikev2 config --generate [-o OUTPUT]
pyikev2 config --validate CONFIG_FILE

# Testing
pyikev2 test [-v]
```

### Python API

```python
from pyikev2 import IKEv2Daemon, IKEv2SA, Config

# Create and configure daemon
config = Config('/etc/pyikev2/config.yaml')
daemon = IKEv2Daemon(config)

# Start daemon
daemon.start()

# Initiate connection
sa = daemon.initiate('203.0.113.1', 500)

# Check established SAs
established = daemon.get_established_sas()
for sa in established:
    print(f"SA: {sa.spi_i.hex()} <-> {sa.spi_r.hex()}")

# Stop daemon
daemon.stop()
```

## Architecture

### Module Structure

- `pyikev2/const.py`: Protocol constants and enumerations
- `pyikev2/message.py`: IKEv2 message structure
- `pyikev2/payloads.py`: All IKEv2 payload implementations
- `pyikev2/crypto.py`: Cryptographic operations
- `pyikev2/state.py`: IKEv2 state machine and SA management
- `pyikev2/daemon.py`: Network daemon and packet handling
- `pyikev2/config.py`: Configuration management
- `pyikev2/cli.py`: Command-line interface

### Protocol Implementation

The implementation follows RFC 7296 strictly:

1. **Message Structure**: Complete IKEv2 header and payload chain
2. **Exchange Types**: IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL
3. **Payloads**: All standard payloads (SA, KE, IDi/r, AUTH, NONCE, NOTIFY, DELETE, VENDOR, TSi/r, SK, CP, EAP)
4. **Cryptographic Suites**: Modern algorithms including AEAD ciphers
5. **State Machine**: Proper state transitions and error handling

## Configuration

### Configuration File Format

Configuration files can be in YAML or JSON format:

```yaml
daemon:
  local_addresses: ['0.0.0.0', '::']
  local_port: 500
  nat_port: 4500
  log_level: INFO
  log_file: /var/log/pyikev2.log
  retransmit_timeout: 2.0
  max_retransmits: 5

crypto:
  proposals:
    - encryption:
        - algorithm: aes256-gcm
        - algorithm: aes128-gcm
        - algorithm: chacha20-poly1305
      integrity: ['none']
      prf: ['hmac-sha256', 'hmac-sha384']
      dh_group: ['curve25519', 'ecp256', 'modp2048']

connections:
  connection-name:
    type: tunnel
    auth_method: psk
    psk: 'pre-shared-key'
    local:
      id: 'local-id'
      subnet: '10.0.0.0/8'
    remote:
      id: 'remote-id'
      subnet: '192.168.0.0/16'
```

### Supported Algorithms

#### Encryption
- AES-CBC (128/192/256 bit)
- AES-CTR (128/192/256 bit)
- AES-GCM (8/12/16 byte ICV)
- 3DES-CBC
- ChaCha20-Poly1305

#### Integrity
- HMAC-MD5-96
- HMAC-SHA1-96
- HMAC-SHA256-128
- HMAC-SHA384-192
- HMAC-SHA512-256
- AES-XCBC-96

#### PRF
- HMAC-MD5
- HMAC-SHA1
- HMAC-SHA256
- HMAC-SHA384
- HMAC-SHA512
- AES128-XCBC
- AES128-CMAC

#### DH Groups
- MODP: 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192
- ECP: P-256, P-384, P-521
- Curve25519, Curve448

## Testing

Run the test suite:

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=pyikev2

# Run specific test module
python -m unittest pyikev2.tests.TestCrypto
```

## Security Considerations

- **Never expose or log cryptographic keys**
- **Use strong pre-shared keys or certificates**
- **Keep the software updated**
- **Follow security best practices for key management**
- **Configure appropriate DPD (Dead Peer Detection) intervals**
- **Use modern cryptographic algorithms (avoid MD5, SHA1 for new deployments)**

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## References

- [RFC 7296 - Internet Key Exchange Protocol Version 2 (IKEv2)](https://www.rfc-editor.org/rfc/rfc7296.html)
- [RFC 7427 - Signature Authentication in IKEv2](https://www.rfc-editor.org/rfc/rfc7427.html)
- [RFC 5996 - Internet Key Exchange Protocol Version 2 (IKEv2) - Obsoleted by RFC 7296](https://www.rfc-editor.org/rfc/rfc5996.html)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/yourusername/pyikev2).

## Disclaimer

This is a reference implementation for educational and testing purposes. For production use, ensure proper security auditing and testing in your specific environment.

**Important Notice**: This implementation was developed as a proof-of-concept using AI-assisted development with Claude Code. While it aims to comply with RFC 7296, it has not undergone comprehensive security auditing or extensive real-world testing. 

**NO WARRANTY**: This software is provided "as is" without any warranties, express or implied. The authors and contributors are not responsible for any damages or security issues that may arise from using this software. Users should thoroughly test and audit the code before deploying it in any production environment.

For critical or production deployments, consider using well-established, battle-tested IKEv2 implementations such as strongSwan, OpenIKEv2, or vendor-supported solutions.
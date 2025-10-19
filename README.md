# Netcraft.js

A comprehensive Node.js library for building and parsing network packets across multiple protocols. Designed for network security research, OS fingerprinting, protocol analysis, and educational purposes.

## Features

- **Multi-Protocol Support**: TCP, UDP, DNS, ARP, ICMP, IPv4, IPv6, and TLS packet crafting
- **Advanced TCP Options**: Complete support for MSS, Window Scale, SACK, Timestamps, and custom options
- **OS Detection Probes**: Pre-built Nmap-style probe configurations for fingerprinting
- **Protocol Compliance**: RFC-compliant implementations across all supported protocols
- **Zero Dependencies**: Pure Node.js implementation with built-in modules only
- **Educational Focus**: Clean, readable code perfect for learning network protocols

---

## Installation

```bash
npm install netcraft-js
```

Or clone this repository:

```bash
git clone https://github.com/Jram2001/tcp-builder.git
cd tcp-builder
```

---

## Quick Start

```javascript
const netcraft = require('netcraft-js');

// TCP SYN packet with advanced options
const tcpPacket = netcraft.tcp.Encode(
    '192.168.1.10', '192.168.1.20', 
    40000, 80, 123456, 0,
    { syn: true }, 65535, 0,
    netcraft.optionBuilder.Probes.T1options,
    Buffer.alloc(0)
);

// DNS query packet
const dnsQuery = netcraft.dns.buildQuery(
    'example.com', 'A', 1, 0x1234
);

// ARP request
const arpRequest = netcraft.arp.buildRequest(
    '192.168.1.1', '00:11:22:33:44:55',
    '192.168.1.100', '00:00:00:00:00:00'
);

console.log('TCP packet:', tcpPacket.toString('hex'));
```

---

## Protocol Support

### TCP (Transmission Control Protocol)

Complete TCP packet crafting with advanced options support for OS fingerprinting and security research.

```javascript
const { tcp, optionBuilder } = require('netcraft-js');

// Custom SYN packet with MSS and Window Scale
const options = optionBuilder.optPadding(Buffer.concat([
    optionBuilder.optMSS(1460),
    optionBuilder.optWScale(7),
    optionBuilder.optSACK(),
    optionBuilder.optTimestamp()
]));

const packet = tcp.Encode(
    '10.0.0.1', '10.0.0.2', 12345, 443,
    1000000, 0, { syn: true }, 29200, 0,
    options, Buffer.alloc(0)
);

// Decode captured packets
const decoded = tcp.Decode(packet);
console.log('Parsed:', decoded);
```

### DNS (Domain Name System)

Build and parse DNS queries and responses for various record types.

```javascript
const { dns } = require('netcraft-js');

// A record query
const aQuery = dns.buildQuery('google.com', 'A', 1, 0x1234);

// MX record query
const mxQuery = dns.buildQuery('example.org', 'MX', 1, 0x5678);

// Parse DNS responses
const response = dns.parseResponse(responseBuffer);
```

### ARP (Address Resolution Protocol)

Create ARP requests and responses for network discovery and analysis.

```javascript
const { arp } = require('netcraft-js');

// ARP request (who-has)
const request = arp.buildRequest(
    '192.168.1.1', '00:11:22:33:44:55',  // Sender IP/MAC
    '192.168.1.100', '00:00:00:00:00:00' // Target IP/MAC
);

// ARP response (is-at)
const response = arp.buildResponse(
    '192.168.1.100', 'aa:bb:cc:dd:ee:ff', // Sender IP/MAC
    '192.168.1.1', '00:11:22:33:44:55'   // Target IP/MAC
);
```

### ICMP (Internet Control Message Protocol)

Generate ICMP packets for ping, traceroute, and network diagnostics.

```javascript
const { icmp } = require('netcraft-js');

// Echo request (ping)
const pingPacket = icmp.buildEchoRequest(1, 1, Buffer.from('Hello'));

// Destination unreachable
const unreachable = icmp.buildDestUnreachable(3, originalPacket);
```

### IPv4 and IPv6

Low-level IP packet construction for custom protocol implementations.

```javascript
const { ipv4, ipv6 } = require('netcraft-js');

// IPv4 packet
const ipv4Packet = ipv4.buildPacket(
    '192.168.1.1', '192.168.1.2', 
    6, tcpPayload // Protocol 6 = TCP
);

// IPv6 packet  
const ipv6Packet = ipv6.buildPacket(
    '2001:db8::1', '2001:db8::2',
    6, tcpPayload
);
```

### UDP (User Datagram Protocol)

Simple UDP packet construction for connectionless protocols.

```javascript
const { udp } = require('netcraft-js');

const udpPacket = udp.Encode(
    '192.168.1.1', '192.168.1.2',
    53, 12345, dnsQuery
);
```

### TLS Analysis

Tools for analyzing TLS handshakes and certificate information.

```javascript
const { tls } = require('netcraft-js');

// Parse TLS handshake messages
const handshake = tls.parseHandshake(tlsBuffer);
const certificates = tls.extractCertificates(handshake);
```

---

## Advanced Features

### OS Fingerprinting Probes

Pre-configured TCP option combinations used by Nmap for OS detection:

```javascript
const { optionBuilder } = require('netcraft-js');

// Nmap T1-T7 probes
const probes = [
    optionBuilder.Probes.T1options,
    optionBuilder.Probes.T2options,
    optionBuilder.Probes.T3options,
    // ... T4-T7
    optionBuilder.Probes.ECNoptions
];

// OS-specific signatures
const linuxProbe = optionBuilder.Probes.LINUXprobe;
const windowsProbe = optionBuilder.Probes.WINDOWSprobe;
```

### Custom TCP Options

Build complex TCP option combinations:

```javascript
const { optionBuilder } = require('netcraft-js');

const customOptions = Buffer.concat([
    optionBuilder.optMSS(1460),
    optionBuilder.optNOP(),
    optionBuilder.optWScale(8),
    optionBuilder.optNOP(),
    optionBuilder.optSACK(),
    optionBuilder.optTimestamp(0x12345678, 0x87654321),
    optionBuilder.optEOL()
]);
```

---

## Use Cases

### Network Security Research

- Custom packet crafting for vulnerability testing
- Protocol fuzzing and edge case analysis
- Firewall and IDS evasion technique development

### OS Fingerprinting

- Active OS detection using TCP/IP stack differences
- Service version detection through protocol analysis
- Network asset discovery and enumeration

### Protocol Analysis

- Educational protocol dissection and learning
- Custom protocol development and testing
- Network troubleshooting and diagnostics

### Traffic Simulation

- Realistic network traffic generation
- Load testing and performance analysis
- Network behavior modeling

---

## Technical Details

### Checksum Calculation

All protocols implement proper checksum calculation following their respective RFCs:

```javascript
const { tcp } = require('netcraft-js');

// Automatic TCP checksum with pseudo-header
const checksum = tcp.TCPChecksum('192.168.1.1', '192.168.1.2', tcpSegment);
```

### Buffer Management

All packet operations use Node.js Buffer objects for efficient binary data handling:

```javascript
// Packet building returns Buffer objects
const packet = tcp.Encode(/* parameters */); // Returns Buffer
const parsed = tcp.Decode(packet);          // Accepts Buffer input
```

### Protocol Compliance

- **RFC 793**: TCP specification compliance
- **RFC 768**: UDP specification
- **RFC 1035**: DNS message format
- **RFC 826**: ARP protocol
- **RFC 792**: ICMP specification
- **RFC 2460**: IPv6 specification
- Network byte order (big-endian) for all multi-byte fields

---

## Installation & Dependencies

This library requires Node.js and has zero external dependencies, using only built-in modules:

- `buffer` - Binary data manipulation
- `crypto` - Checksum calculations
- No external packages required

---

## Testing

```bash
node test.js
```

Example test scenarios:

- Packet encoding/decoding round-trips
- Checksum validation across protocols
- Option parsing correctness
- Cross-protocol integration

---

## Important Notes

- **Privileges**: Raw packet transmission requires root/administrator privileges
- **Legal Use**: Only use for authorized testing and educational purposes
- **Network Impact**: Be mindful of generated traffic on production networks
- **Compliance**: Ensure usage complies with local laws and network policies

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add comprehensive tests for new functionality
4. Ensure all existing tests pass
5. Follow existing code style and documentation patterns
6. Submit a pull request with detailed description

---

## License

MIT License - see LICENSE file for details.

---

## Version History

- **v2.6.2**: Multi-protocol support with DNS, ARP, ICMP, IPv6, UDP, TLS
- **v1.x**: TCP-only packet builder with basic options support

---

## Author

Built by a full-stack developer transitioning into cybersecurity, focused on creating educational tools for network protocol understanding and security research.

---

## Disclaimer

This tool is intended for educational purposes, authorized security testing, and network research only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before use.
# TCP Packet Builder

A comprehensive Node.js library for building and parsing custom TCP packets with advanced options support. Designed for network security research, OS fingerprinting, and protocol analysis.

## Features

- **Complete TCP packet encoding/decoding** with proper checksum calculation
- **Advanced TCP options support** including MSS, Window Scale, SACK, and Timestamps
- **Pre-built probe configurations** for OS detection (Nmap-style probes)
- **Protocol-compliant** implementation following RFC 793 and related standards
- **Zero dependencies** - pure Node.js implementation

## Installation

```bash
npm install tcp-builder
```

Or clone this repository:
```bash
git clone <repository-url>
cd tcp-builder
```

## Quick Start

```javascript
const TCP = require('tcp-builder');

// Create a basic SYN packet
const synPacket = TCP.Encode(
    '192.168.1.10',    // Source IP
    '192.168.1.20',    // Destination IP
    40000,             // Source Port
    80,                // Destination Port
    123456,            // Sequence Number
    0,                 // Acknowledgment Number
    { syn: true },     // Flags
    65535,             // Window Size
    0,                 // Urgent Pointer
    Buffer.alloc(0),   // Options
    Buffer.alloc(0)    // Data
);

console.log('Packet hex:', synPacket.toString('hex'));

// Decode the packet
const decoded = TCP.Decode(synPacket);
console.log('Decoded:', decoded);
```

## API Reference

### TCP.Encode(srcIp, destIp, srcPort, destPort, seqNumber, ackNumber, flags, windowSize, urgentPointer, options, data)

Builds a complete TCP packet with proper header structure and checksum.

**Parameters:**
- `srcIp` (string): Source IP address for checksum calculation
- `destIp` (string): Destination IP address for checksum calculation  
- `srcPort` (number): Source port number (0-65535)
- `destPort` (number): Destination port number (0-65535)
- `seqNumber` (number): Sequence number (32-bit, default: 0)
- `ackNumber` (number): Acknowledgment number (32-bit, default: 0)
- `flags` (object): TCP flags object with boolean properties:
  - `fin`: Connection termination
  - `syn`: Synchronize sequence numbers
  - `rst`: Reset connection
  - `psh`: Push data to application
  - `ack`: Acknowledgment field valid
  - `urg`: Urgent pointer valid
  - `ece`: ECN Echo
  - `cwr`: Congestion Window Reduced
- `windowSize` (number): Receive window size (16-bit, default: 65535)
- `urgentPointer` (number): Urgent pointer (16-bit, default: 0)
- `options` (Buffer): TCP options (variable length)
- `data` (Buffer): Payload data

**Returns:** Buffer containing the complete TCP packet

### TCP.Decode(packet, skipIPHeader)

Parses a TCP packet and extracts all header fields.

**Parameters:**
- `packet` (Buffer): TCP packet buffer to decode
- `skipIPHeader` (boolean): If true, skips first 20 bytes (IP header)

**Returns:** Object containing:
- `sourcePort`: Source port number
- `destinationPort`: Destination port number
- `sequenceNumber`: Sequence number
- `acknowledgmentNumber`: Acknowledgment number
- `dataOffset`: Header length in 32-bit words
- `flags`: Array of active flag names
- `windowSize`: Window size value
- `checksum`: Checksum value
- `urgentPointer`: Urgent pointer value
- `options`: Array of parsed option objects
- `dataPayload`: Data payload buffer

## TCP Options

### Available Option Builders

```javascript
const { OptionBuilders } = require('tcp-builder');

// Maximum Segment Size
const mssOption = OptionBuilders.optMSS(1460);

// Window Scale
const windowScale = OptionBuilders.optWScale(7);

// SACK Permitted
const sackPermitted = OptionBuilders.optSACK();

// Timestamps
const timestamp = OptionBuilders.optTimestamp(0xFFFFFFFF, 0);

// No Operation (padding)
const nop = OptionBuilders.optNOP();

// End of Options List
const eol = OptionBuilders.optEOL();

// Combine options with proper padding
const options = OptionBuilders.optPadding(
    Buffer.concat([mssOption, windowScale, sackPermitted, timestamp])
);
```

### Option Types Supported

| Option | Kind | Description | RFC |
|--------|------|-------------|-----|
| EOL | 0 | End of Option List | 793 |
| NOP | 1 | No Operation (padding) | 793 |
| MSS | 2 | Maximum Segment Size | 793 |
| WScale | 3 | Window Scale | 7323 |
| SACK | 4 | SACK Permitted | 2018 |
| Timestamps | 8 | Timestamp Option | 7323 |

## Pre-built Probe Configurations

The library includes pre-configured probe options for OS detection:

```javascript
const { Probes } = require('tcp-builder');

// Nmap-style probes
const t1Packet = TCP.Encode(
    '192.168.1.10', '192.168.1.20', 40000, 80,
    123456, 0, { syn: true }, 65535, 0,
    Probes.T1options,  // Pre-built T1 probe options
    Buffer.alloc(0)
);

// Available probe types:
// T1options - T7options: Standard Nmap TCP probes
// ECNoptions: ECN probe configuration
// MSSonly, WSCALEonly, SACKonly: Single option probes
// LINUXprobe, WINDOWSprobe, BSDprobe: OS-specific probes
```

## Advanced Examples

### Custom SYN Packet with Options

```javascript
const { OptionBuilders } = require('tcp-builder');

// Build custom options
const options = OptionBuilders.optPadding(Buffer.concat([
    OptionBuilders.optMSS(1460),
    OptionBuilders.optWScale(7),
    OptionBuilders.optSACK(),
    OptionBuilders.optTimestamp()
]));

const packet = TCP.Encode(
    '10.0.0.1', '10.0.0.2', 12345, 443,
    1000000, 0, { syn: true }, 29200, 0,
    options, Buffer.alloc(0)
);
```

### TCP Packet with Data Payload

```javascript
const data = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');

const packet = TCP.Encode(
    '192.168.1.100', '93.184.216.34', 54321, 80,
    2000000, 1000000, { psh: true, ack: true }, 65535, 0,
    Buffer.alloc(0), data
);
```

### Decoding Captured Packets

```javascript
// Assuming you have a raw TCP packet buffer
const rawPacket = Buffer.from('504f...', 'hex');
const parsed = TCP.Decode(rawPacket);

console.log('Source Port:', parsed.sourcePort);
console.log('Flags:', parsed.flags);
console.log('Options:', parsed.options);
```

## Checksum Calculation

The library automatically calculates proper TCP checksums using the pseudo-header approach:

```javascript
const { TCPChecksum } = require('tcp-builder');

// Manual checksum calculation (usually not needed)
const checksum = TCPChecksum('192.168.1.1', '192.168.1.2', tcpSegmentBuffer);
```

## Protocol Compliance

- **RFC 793**: Transmission Control Protocol specification
- **RFC 2018**: SACK (Selective Acknowledgment) support
- **RFC 7323**: TCP Extensions for High Performance (Window Scale, Timestamps)
- **Network byte order**: All multi-byte fields use big-endian encoding
- **Proper padding**: TCP options are automatically padded to 4-byte boundaries

## Use Cases

- **Network security research**: Custom packet crafting for vulnerability testing
- **OS fingerprinting**: Using probe configurations to identify remote systems
- **Protocol analysis**: Building test packets for network protocol research
- **Traffic simulation**: Generating realistic TCP traffic patterns
- **Educational purposes**: Understanding TCP packet structure and options

## Important Notes

1. **Privileges Required**: Sending raw TCP packets typically requires root/administrator privileges
2. **Checksum Validation**: Checksums are calculated over pseudo-header + TCP segment
3. **Option Padding**: TCP options are automatically padded to maintain 32-bit alignment
4. **Buffer Management**: All inputs/outputs use Node.js Buffer objects for binary data

## Testing

```bash
node test.js
```

Example test output:
```
Decoded fields: {
  sourcePort: 40000,
  destinationPort: 80,
  sequenceNumber: 123456,
  acknowledgmentNumber: 0,
  dataOffset: 5,
  flags: [ 'SYN' ],
  windowSize: 65535,
  checksum: 44449,
  urgentPointer: 0,
  options: [],
  dataPayload: <Buffer >
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Dependencies

This library has zero external dependencies and uses only Node.js built-in modules.

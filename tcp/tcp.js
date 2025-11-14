const { optPadding } = require("../option-bulder");
const { tcpCheckSum } = require("./tcp-checksum");

/**
 * TCP Packet Encoder/Decoder
 * Implements RFC 793 TCP segment structure with proper header formatting and checksum validation
 * 
 * TCP Header Structure (20 bytes minimum, up to 60 bytes with options):
 * - Bytes 0-1:   Source Port
 * - Bytes 2-3:   Destination Port
 * - Bytes 4-7:   Sequence Number
 * - Bytes 8-11:  Acknowledgment Number
 * - Byte 12:     Data Offset (4 bits) + Reserved (4 bits)
 * - Byte 13:     TCP Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
 * - Bytes 14-15: Window Size
 * - Bytes 16-17: Checksum
 * - Bytes 18-19: Urgent Pointer
 * - Bytes 20+:   Options (if present) + Padding
 */

/**
 * Encodes a complete TCP segment with header and optional payload
 * 
 * @param {string} srcIp - Source IP address (for pseudo-header checksum)
 * @param {string} destIp - Destination IP address (for pseudo-header checksum)
 * @param {number} srcPort - Source port (0-65535)
 * @param {number} destPort - Destination port (0-65535)
 * @param {number} [seqNumber=0] - Sequence number
 * @param {number} [ackNumber=0] - Acknowledgment number
 * @param {Object} [flags={}] - TCP flags: {fin, syn, rst, psh, ack, urg, ece, cwr}
 * @param {number} [windowSize=65535] - Receive window size
 * @param {number} [urgentPointer=0] - Urgent data pointer
 * @param {Buffer} [options=Buffer.alloc(0)] - TCP options buffer
 * @param {Buffer} [data=Buffer.alloc(0)] - Payload data
 * @returns {Buffer} Complete TCP segment (header + data)
 */
function Encode(
    srcIp,
    destIp,
    srcPort,
    destPort,
    seqNumber = 0,
    ackNumber = 0,
    flags = {},
    windowSize = 65535,
    urgentPointer = 0,
    options = Buffer.alloc(0),
    data = Buffer.alloc(0)
) {
    if (!isValidIP(srcIp) || !isValidIP(destIp)) {
        console.warn("Invalid source or destination IP address:", srcIp, destIp);
        return Buffer.alloc(0);
    }

    // Pad options to 32-bit word boundary (required by TCP spec)
    const paddedOptions = optPadding(options, 'options');

    // Allocate header buffer (20-byte base + options)
    const headerSize = 20 + paddedOptions.length;
    const header = Buffer.alloc(headerSize);

    // Write fixed header fields
    header.writeUInt16BE(srcPort, 0);
    header.writeUInt16BE(destPort, 2);
    header.writeUInt32BE(seqNumber, 4);
    header.writeUInt32BE(ackNumber, 8);

    // Build data offset and flags field (bytes 12-13)
    const dataOffset = headerSize / 4; // Header length in 32-bit words
    const offsetAndReserved = dataOffset << 12;

    // Encode TCP flags
    const flagBits = (
        (flags.fin ? 0x01 : 0) |
        (flags.syn ? 0x02 : 0) |
        (flags.rst ? 0x04 : 0) |
        (flags.psh ? 0x08 : 0) |
        (flags.ack ? 0x10 : 0) |
        (flags.urg ? 0x20 : 0) |
        (flags.ece ? 0x40 : 0) |
        (flags.cwr ? 0x80 : 0)
    );

    header.writeUInt16BE(offsetAndReserved | flagBits, 12);
    header.writeUInt16BE(windowSize, 14);
    header.writeUInt16BE(urgentPointer, 18);

    // Copy padded options to header
    if (paddedOptions.length > 0) {
        paddedOptions.copy(header, 20);
    }

    // Calculate checksum over TCP segment with pseudo-header
    const tcpSegmentTemp = Buffer.concat([header, data]);
    const checksum = tcpCheckSum(srcIp, destIp, tcpSegmentTemp);
    header.writeUInt16BE(checksum, 16);

    // Return complete TCP segment
    return Buffer.concat([header, data]);
}

/**
 * Decodes a TCP packet into structured components
 * 
 * @param {Buffer} packet - Raw packet buffer
 * @param {boolean} [skipIPHeader=false] - Skip first 20 bytes if IP header is present
 * @returns {Object|Buffer} Parsed TCP packet object or empty buffer on error
 */
function Decode(packet, skipIPHeader = false) {
    if (!Buffer.isBuffer(packet)) {
        console.warn("Packet must be a Buffer");
        return Buffer.alloc(0);
    }

    const tcpStart = skipIPHeader ? 20 : 0;
    const minPacketSize = tcpStart + 20;

    if (packet.length < minPacketSize) {
        console.warn("Packet too small for TCP header");
        return Buffer.alloc(0);
    }

    const output = {};

    // Parse fixed header fields
    output.sourcePort = packet.readUInt16BE(tcpStart + 0);
    output.destinationPort = packet.readUInt16BE(tcpStart + 2);
    output.sequenceNumber = packet.readUInt32BE(tcpStart + 4);
    output.acknowledgmentNumber = packet.readUInt32BE(tcpStart + 8);

    // Parse data offset and validate reserved bits
    const dataOffsetByte = packet.readUInt8(tcpStart + 12);
    const dataOffset = (dataOffsetByte >> 4) & 0x0F;
    const reserved = dataOffsetByte & 0x0E; // Bits 1-3 of lower nibble

    if (reserved !== 0) {
        console.warn("Non-zero reserved bits detected");
        return Buffer.alloc(0);
    }

    const availableLength = packet.length - tcpStart;
    if (!isValidDataOffset(dataOffset, availableLength)) {
        return Buffer.alloc(0);
    }

    output.dataOffset = dataOffset;
    output.flags = parseFlags(packet.readUInt8(tcpStart + 13));
    output.windowSize = packet.readUInt16BE(tcpStart + 14);
    output.checksum = packet.readUInt16BE(tcpStart + 16);
    output.urgentPointer = packet.readUInt16BE(tcpStart + 18);

    // Parse options if present
    const headerLength = dataOffset * 4;
    if (headerLength > 20) {
        const optionsLength = headerLength - 20;
        const optionsBuffer = packet.slice(tcpStart + 20, tcpStart + 20 + optionsLength);
        output.options = parseOptions(optionsBuffer);
    } else {
        output.options = [];
    }

    // Extract payload
    output.dataPayload = packet.slice(tcpStart + headerLength);

    return output;
}

/**
 * Converts TCP flag byte to array of active flags
 * @param {number} flagBits - 8-bit flag field
 * @returns {string[]} Array of active flag names
 */
function parseFlags(flagBits) {
    const bits = flagBits.toString(2).padStart(8, '0');
    const flags = ['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'];
    return flags.filter((_, index) => bits[index] === '1');
}

/**
 * Parses TCP options field
 * @param {Buffer} optionsBuffer - Raw options buffer
 * @returns {Array} Array of parsed option objects
 */
function parseOptions(optionsBuffer) {
    if (!Buffer.isBuffer(optionsBuffer)) {
        console.warn("Options must be a Buffer");
        return [];
    }

    const OPTION_TYPES = {
        0: 'EOL',
        1: 'NOP',
        2: 'MSS',
        3: 'WS',
        4: 'SACK-Permitted',
        5: 'SACK',
        8: 'Timestamps',
        14: 'AltChkSum',
        15: 'AltChkSumData'
    };

    const MIN_LENGTHS = { 2: 4, 3: 3, 4: 2, 5: 10, 8: 10, 14: 3, 15: 2 };
    const MAX_LENGTHS = { 2: 4, 3: 3, 4: 2, 5: 34, 8: 10, 14: 3, 15: 40 };

    const options = [];
    let i = 0;

    while (i < optionsBuffer.length) {
        const kind = optionsBuffer[i];

        // End of Option List
        if (kind === 0) {
            options.push({ type: 'EOL', kind: 0 });
            break;
        }

        // No Operation (padding)
        if (kind === 1) {
            options.push({ type: 'NOP', kind: 1 });
            i++;
            continue;
        }

        // Check if length byte exists
        if (i + 1 >= optionsBuffer.length) {
            console.warn(`Option kind ${kind} missing length byte at position ${i}`);
            break;
        }

        const length = optionsBuffer[i + 1];

        if (isInvalidOptionLength(kind, length, i, optionsBuffer.length, MIN_LENGTHS, MAX_LENGTHS, OPTION_TYPES)) {
            return [];
        }

        const data = optionsBuffer.slice(i + 2, i + length);
        options.push({
            type: OPTION_TYPES[kind] || `Unknown-${kind}`,
            kind,
            length,
            data
        });

        i += length;
    }

    return options;
}

/**
 * Validates TCP option length field
 * @returns {boolean} True if option is malformed
 */
function isInvalidOptionLength(kind, length, currentIndex, bufferLength, minLengths, maxLengths, optionTypes) {
    // Length must be at least 2 (kind + length bytes)
    if (length < 2) {
        console.warn(`Option kind ${kind} has invalid length ${length} (minimum is 2)`);
        return true;
    }

    // Validate minimum length for known options
    if (minLengths[kind] && length < minLengths[kind]) {
        console.warn(`Option kind ${kind} length ${length} is below minimum ${minLengths[kind]}`);
        return true;
    }

    // Validate maximum length for known options
    if (maxLengths[kind] && length > maxLengths[kind]) {
        console.warn(`Option kind ${kind} length ${length} exceeds maximum ${maxLengths[kind]}`);
        return true;
    }

    // Length must not exceed remaining buffer
    if (currentIndex + length > bufferLength) {
        console.warn(`Option kind ${kind} extends beyond buffer bounds`);
        return true;
    }

    // Cap unknown option lengths to prevent DoS
    if (!optionTypes[kind] && length > 40) {
        console.warn(`Unknown option kind ${kind} has excessive length ${length}`);
        return true;
    }

    // SACK-specific validation: length must be 2 + 8n
    if (kind === 5 && (length - 2) % 8 !== 0) {
        console.warn(`SACK option has invalid length ${length} (must be 2 + 8n bytes)`);
        return true;
    }

    return false;
}

/**
 * Validates TCP data offset field
 * @param {number} dataOffset - Data offset in 32-bit words
 * @param {number} packetLength - Total packet length
 * @returns {boolean} True if valid
 */
function isValidDataOffset(dataOffset, packetLength) {
    const headerLength = dataOffset * 4;

    if (headerLength < 20 || headerLength > 60) {
        console.warn(`Invalid data offset: ${dataOffset} (header length: ${headerLength} bytes)`);
        return false;
    }

    if (packetLength < headerLength) {
        console.warn(`Packet size ${packetLength} is smaller than header length ${headerLength}`);
        return false;
    }

    return true;
}

/**
 * Validates IPv4 address format
 * @param {string} ipAddress - IP address string
 * @returns {boolean} True if valid IPv4 address
 */
function isValidIP(ipAddress) {
    const octets = ipAddress.split('.').map(n => parseInt(n, 10));

    if (octets.length !== 4) {
        return false;
    }

    return octets.every(n => !Number.isNaN(n) && n >= 0 && n <= 255);
}

module.exports = {
    Encode,
    Decode,
    OptionBuilders: require('../option-bulder'),
    Probes: require('./tcp-option-probes'),
    TCPChecksum: require('./tcp-checksum')
};

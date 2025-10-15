// ipv4-encoder.js
// Main IPv4 packet encoder

const {
    processOptions,
    processFlagsAndOffset,
    processProtocol,
    onesComplementSum,
    processIP,
    validateParameters
} = require('./utils');

/**
 * Encode an IPv4 packet with the given parameters
 * 
 * @param {string} srcIp - Source IP address (e.g., '192.168.1.1')
 * @param {string} destIp - Destination IP address (e.g., '192.168.1.2')
 * @param {number} version - IP version (must be 4)
 * @param {number} DSCP - Differentiated Services Code Point (0-63)
 * @param {number} ECN - Explicit Congestion Notification (0-3)
 * @param {number} identification - Identification field (0-65535)
 * @param {string} flag - Flags string (can contain 'df' and/or 'mf')
 * @param {number} fragmentOffset - Fragment offset (0-8191)
 * @param {number} ttl - Time to Live (0-255)
 * @param {string} protocol - Protocol name (e.g., 'tcp', 'udp', 'icmp')
 * @param {Array} userOptions - Array of IPv4 option objects
 * @param {Buffer} payload - Packet payload as a Buffer
 * @returns {Buffer} Complete IPv4 packet
 * 
 * @example
 * const payload = Buffer.from('Hello, World!', 'utf8');
 * const packet = Encode(
 *     '192.168.1.1',
 *     '192.168.1.2',
 *     4,
 *     0,
 *     0,
 *     12345,
 *     'df',
 *     0,
 *     64,
 *     'tcp',
 *     [],
 *     payload
 * );
 */
function Encode(srcIp, destIp, version, DSCP, ECN, identification, flag, fragmentOffset, ttl, protocol, userOptions, payload) {
    // Validate all parameters
    validateParameters({
        version,
        DSCP,
        ECN,
        identification,
        fragmentOffset,
        ttl,
        payload
    });

    // Process components
    const header = Buffer.alloc(20);
    const options = processOptions(userOptions);
    const headerLengthBytes = 20 + options.length;
    const IHL = headerLengthBytes / 4;

    // Validate IHL (Internet Header Length)
    if (IHL > 15) {
        throw new Error('Options too large (max 40 bytes)');
    }

    if (IHL !== Math.floor(IHL)) {
        throw new Error('Invalid options length (must be multiple of 4)');
    }

    // Validate total packet size
    const totalLength = headerLengthBytes + payload.length;
    if (totalLength > 65535) {
        throw new Error('Packet exceeds maximum IPv4 size (65535 bytes)');
    }

    // Process flags, offset, and protocol
    const FOA = processFlagsAndOffset(flag, fragmentOffset);
    const processedProtocol = processProtocol(protocol);

    // Build IPv4 header (20 bytes)
    // Byte 0: Version (4 bits) + IHL (4 bits)
    header.writeUInt8((version << 4) | (IHL & 0x0F), 0);

    // Byte 1: DSCP (6 bits) + ECN (2 bits)
    header.writeUInt8((DSCP << 2) | ECN, 1);

    // Bytes 2-3: Total Length
    header.writeUInt16BE(totalLength, 2);

    // Bytes 4-5: Identification
    header.writeUInt16BE(identification, 4);

    // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
    header.writeUInt16BE(FOA, 6);

    // Byte 8: Time to Live
    header.writeUInt8(ttl, 8);

    // Byte 9: Protocol
    header.writeUInt8(processedProtocol, 9);

    // Bytes 10-11: Header Checksum (placeholder, calculated below)
    header.writeUInt16BE(0, 10);

    // Bytes 12-15: Source IP Address
    header.writeUInt32BE(processIP(srcIp), 12);

    // Bytes 16-19: Destination IP Address
    header.writeUInt32BE(processIP(destIp), 16);

    // Calculate and set checksum
    const checksum = onesComplementSum(Buffer.concat([header, options]));
    header.writeUInt16BE(checksum, 10);

    // Construct and return final packet
    return Buffer.concat([header, options, payload]);
}

/**
 * Decode basic information from an IPv4 packet
 * @param {Buffer} packet - IPv4 packet buffer
 * @returns {Object} Decoded packet information
 */
function DecodeHeader(packet) {
    if (!Buffer.isBuffer(packet) || packet.length < 20) {
        throw new Error('Invalid packet: must be a Buffer with at least 20 bytes');
    }

    const versionIHL = packet.readUInt8(0);
    const version = (versionIHL >> 4) & 0x0F;
    const IHL = versionIHL & 0x0F;
    const headerLength = IHL * 4;

    const dscpEcn = packet.readUInt8(1);
    const DSCP = (dscpEcn >> 2) & 0x3F;
    const ECN = dscpEcn & 0x03;

    const totalLength = packet.readUInt16BE(2);
    const identification = packet.readUInt16BE(4);

    const flagsOffset = packet.readUInt16BE(6);
    const flags = (flagsOffset >> 13) & 0x07;
    const fragmentOffset = flagsOffset & 0x1FFF;

    const ttl = packet.readUInt8(8);
    const protocol = packet.readUInt8(9);
    const checksum = packet.readUInt16BE(10);

    const srcIp = [
        packet.readUInt8(12),
        packet.readUInt8(13),
        packet.readUInt8(14),
        packet.readUInt8(15)
    ].join('.');

    const destIp = [
        packet.readUInt8(16),
        packet.readUInt8(17),
        packet.readUInt8(18),
        packet.readUInt8(19)
    ].join('.');

    return {
        version,
        IHL,
        headerLength,
        DSCP,
        ECN,
        totalLength,
        identification,
        flags: {
            DF: !!(flags & 0b010),
            MF: !!(flags & 0b001)
        },
        fragmentOffset,
        ttl,
        protocol,
        checksum,
        srcIp,
        destIp,
        hasOptions: IHL > 5,
        optionsLength: headerLength - 20
    };
}

// Example usage
if (require.main === module) {
    console.log('IPv4 Packet Encoder - Example Usage\n');

    // Create a simple packet
    const payload = Buffer.from('Hello, IPv4 World!', 'utf8');

    const packet = Encode(
        '192.168.1.100',  // Source IP
        '8.8.8.8',        // Destination IP (Google DNS)
        4,                // IPv4
        0,                // DSCP (default)
        0,                // ECN (not set)
        54321,            // Identification
        'df',             // Don't Fragment flag
        0,                // Fragment offset
        64,               // TTL
        'tcp',            // Protocol
        [],               // No options
        payload           // Payload
    );

    console.log('Encoded Packet:');
    console.log('Length:', packet.length, 'bytes');
    console.log('Hex:', packet.toString('hex'));
    console.log('\nDecoded Header:');
    console.log(DecodeHeader(packet));

    // Example with options
    console.log('\n--- Packet with Record Route Option ---\n');

    const packetWithOptions = Encode(
        '10.0.0.1',
        '10.0.0.2',
        4,
        0,
        0,
        12345,
        '',               // No flags
        0,
        128,
        'udp',
        [{ type: 'RR', length: 11 }],  // Record Route with space for 2 IPs
        payload
    );

    console.log('Encoded Packet with Options:');
    console.log('Length:', packetWithOptions.length, 'bytes');
    console.log('Hex:', packetWithOptions.toString('hex'));
    console.log('\nDecoded Header:');
    console.log(DecodeHeader(packetWithOptions));
}

module.exports = { Encode, DecodeHeader };
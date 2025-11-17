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

const {
    checkAndRead16,
    checkAndWrite16,
    checkAndRead8,
    checkAndWrite8
} = require("../util");

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
    checkAndWrite8(header, (version << 4) | (IHL & 0x0F), 0);

    // Byte 1: DSCP (6 bits) + ECN (2 bits)
    checkAndWrite8(header, (DSCP << 2) | ECN, 1);

    // Bytes 2-3: Total Length
    checkAndWrite16(header, totalLength, 2);

    // Bytes 4-5: Identification
    checkAndWrite16(header, identification, 4);

    // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
    checkAndWrite16(header, FOA, 6);

    // Byte 8: Time to Live
    checkAndWrite8(header, ttl, 8);

    // Byte 9: Protocol
    checkAndWrite8(header, processedProtocol, 9);

    // Bytes 10-11: Header Checksum (placeholder, calculated below)
    checkAndWrite16(header, 0, 10);

    // Bytes 12-15: Source IP Address
    header.writeUInt32BE(processIP(srcIp), 12);

    // Bytes 16-19: Destination IP Address
    header.writeUInt32BE(processIP(destIp), 16);

    // Calculate and set checksum
    const checksum = onesComplementSum(Buffer.concat([header, options]));
    checkAndWrite16(header, checksum, 10);

    // Construct and return final packet
    return Buffer.concat([header, options, payload]);
}

/**
 * Decode basic information from an IPv4 packet
 * @param {Buffer} packet - IPv4 packet buffer
 * @returns {Object} Decoded packet information
 */
function Decode(packet) {
    if (!Buffer.isBuffer(packet) || packet.length < 20) {
        throw new Error('Invalid packet: must be a Buffer with at least 20 bytes');
    }

    const versionIHL = checkAndRead8(packet, 0);
    const version = (versionIHL >> 4) & 0x0F;
    const IHL = versionIHL & 0x0F;
    const headerLength = IHL * 4;


    if (version !== 4) {
        throw new Error('Not an IPv4 packet');
    }
    if (headerLength < 20 || headerLength > 60) {
        throw new Error('Invalid IHL (header length)');
    }
    if (packet.length < headerLength) {
        throw new Error('Buffer shorter than header length');
    }


    const dscpEcn = checkAndRead8(packet, 1);
    const DSCP = (dscpEcn >> 2) & 0x3F;
    const ECN = dscpEcn & 0x03;

    const totalLength = checkAndRead16(packet, 2);

    if (totalLength < headerLength || totalLength > packet.length) {
        throw new Error('Total-length field exceeds actual buffer');
    }

    const identification = checkAndRead16(packet, 4);

    const flagsOffset = checkAndRead16(packet, 6);
    const flags = (flagsOffset >> 13) & 0x07;
    const fragmentOffset = flagsOffset & 0x1FFF;

    const ttl = checkAndRead8(packet, 8);
    const protocol = checkAndRead8(packet, 9);
    const checksum = checkAndRead16(packet, 10);

    const srcIp = [
        checkAndRead8(packet, 12),
        checkAndRead8(packet, 13),
        checkAndRead8(packet, 14),
        checkAndRead8(packet, 15)
    ].join('.');

    const destIp = [
        checkAndRead8(packet, 16),
        checkAndRead8(packet, 17),
        checkAndRead8(packet, 18),
        checkAndRead8(packet, 19)
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
    console.log(Decode(packet));

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
    console.log(Decode(packetWithOptions));
}

module.exports = { Encode, Decode };
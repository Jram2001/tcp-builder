// ipv4-utils.js
// Utility functions for IPv4 packet encoding

/**
 * Process IPv4 options into a properly formatted and padded buffer
 * @param {Array} options - Array of option objects with type and optional data
 * @returns {Buffer} Padded options buffer
 */
function processOptions(options) {
    if (!options || options.length === 0) return Buffer.alloc(0);
    const buffers = [];

    for (const opt of options) {
        if (opt.type === 'EOL') {
            buffers.push(Buffer.from([0]));
            break; // EOL terminates all options
        } else if (opt.type === 'NOP') {
            buffers.push(Buffer.from([1]));
        } else if (opt.type === 'RR') {
            const length = opt.length || 7;

            // Validate RR length: must be 7, 11, 15, 19, 23, 27, 31, 35, or 39
            if (length < 7 || length > 39 || (length - 3) % 4 !== 0) {
                throw new Error(`Invalid RR length: ${length}. Must be 3 + 4n where 1 <= n <= 9`);
            }

            const buf = Buffer.alloc(length);
            buf[0] = 7;      // Type: Record Route
            buf[1] = length; // Length
            buf[2] = 4;      // Pointer (starts after header)
            buffers.push(buf);
        } else if (opt.type === 'LSRR') {
            // Loose Source and Record Route
            const length = opt.length || 7;

            if (length < 7 || length > 39 || (length - 3) % 4 !== 0) {
                throw new Error(`Invalid LSRR length: ${length}. Must be 3 + 4n where 1 <= n <= 9`);
            }

            const buf = Buffer.alloc(length);
            buf[0] = 131;    // Type: LSRR
            buf[1] = length; // Length
            buf[2] = 4;      // Pointer
            buffers.push(buf);
        } else if (opt.type === 'SSRR') {
            // Strict Source and Record Route
            const length = opt.length || 7;

            if (length < 7 || length > 39 || (length - 3) % 4 !== 0) {
                throw new Error(`Invalid SSRR length: ${length}. Must be 3 + 4n where 1 <= n <= 9`);
            }

            const buf = Buffer.alloc(length);
            buf[0] = 137;    // Type: SSRR
            buf[1] = length; // Length
            buf[2] = 4;      // Pointer
            buffers.push(buf);
        } else if (opt.type === 'TS') {
            // Timestamp option
            const length = opt.length || 12;

            if (length < 8 || length > 40 || length % 4 !== 0) {
                throw new Error(`Invalid TS length: ${length}. Must be multiple of 4, between 8-40`);
            }

            const buf = Buffer.alloc(length);
            buf[0] = 68;     // Type: Timestamp
            buf[1] = length; // Length
            buf[2] = 5;      // Pointer
            buf[3] = opt.flags || 0; // Overflow counter and flags
            buffers.push(buf);
        } else if (opt.type === 'RAW') {
            if (!Buffer.isBuffer(opt.data)) {
                throw new Error('RAW option requires a Buffer in .data');
            }
            if (optionBuffer.length > 40) {
                throw new Error('Total options length exceeds maximum (40 bytes)');
            }
            if (opt.data.length === 0) continue;
            buffers.push(opt.data);
        } else {
            throw new Error(`Unsupported option type: ${opt.type}`);
        }
    }

    let optionBuffer = Buffer.concat(buffers);

    // Pad to 4-byte boundary
    const padding = (4 - (optionBuffer.length % 4)) % 4;
    if (padding > 0) {
        optionBuffer = Buffer.concat([optionBuffer, Buffer.alloc(padding)]);
    }

    // Validate total options length
    if (optionBuffer.length > 40) {
        throw new Error('Total options length exceeds maximum (40 bytes)');
    }

    return optionBuffer;
}

/**
 * Process flags and fragment offset into a single 16-bit value
 * @param {string} flags - Flags string (can contain 'df', 'mf')
 * @param {number} offset - Fragment offset (0-8191)
 * @returns {number} Combined flags and offset value
 */
function processFlagsAndOffset(flags, offset) {
    if (typeof flags !== 'string') {
        throw new Error('Flags must be a string');
    }

    let flagBits = 0b000;
    const lowerFlags = flags.toLowerCase();

    // Don't Fragment
    if (lowerFlags.includes('df')) flagBits |= 0b010;
    // More Fragments
    if (lowerFlags.includes('mf')) flagBits |= 0b001;

    // Validate offset range
    if (offset < 0 || offset > 8191) {
        throw new Error('Fragment offset must be 0-8191');
    }

    // Combine: 3 flag bits (shifted left 13) + 13 offset bits
    return (flagBits << 13) | (offset & 0x1FFF);
}

/**
 * Convert protocol name to protocol number
 * @param {string} protocol - Protocol name (e.g., 'tcp', 'udp')
 * @returns {number} Protocol number
 */
function processProtocol(protocol) {
    const protocols = {
        icmp: 1,
        igmp: 2,
        tcp: 6,
        egp: 8,
        pup: 12,
        udp: 17,
        ipv6: 41,
        ospf: 89,
        sctp: 132,
        udplite: 136
    };

    const normalizedProtocol = protocol.toLowerCase();

    if (!(normalizedProtocol in protocols)) {
        throw new Error(`Invalid protocol: ${protocol}. Supported: ${Object.keys(protocols).join(', ')}`);
    }

    return protocols[normalizedProtocol];
}

/**
 * Calculate one's complement checksum for IPv4 header
 * @param {Buffer} packet - Packet buffer to calculate checksum for
 * @returns {number} 16-bit checksum value
 */
function onesComplementSum(packet) {
    let sum = 0;

    // Process 16-bit words
    for (let i = 0; i < packet.length; i += 2) {
        let word;
        if (i + 1 < packet.length) {
            word = (packet[i] << 8) | packet[i + 1];
        } else {
            word = packet[i] << 8; // Pad last byte with zero
        }

        sum += word;

        // Fold carries
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
    }

    return ~sum & 0xFFFF;
}

/**
 * Convert IPv4 address string to 32-bit unsigned integer
 * @param {string} ip - IPv4 address in dotted decimal notation
 * @returns {number} 32-bit unsigned integer representation
 */
function processIP(ip) {
    if (typeof ip !== 'string') {
        throw new Error('IP address must be a string');
    }

    const bytes = ip.split('.');

    if (bytes.length !== 4) {
        throw new Error(`Invalid IP address format: ${ip}`);
    }

    const numBytes = bytes.map(x => parseInt(x, 10));

    // Validate each octet
    for (let i = 0; i < 4; i++) {
        if (isNaN(numBytes[i]) || numBytes[i] < 0 || numBytes[i] > 255) {
            throw new Error(`Invalid IP octet: ${bytes[i]} in ${ip}`);
        }
    }

    // Combine octets and convert to unsigned 32-bit integer
    return ((numBytes[0] << 24) | (numBytes[1] << 16) | (numBytes[2] << 8) | numBytes[3]) >>> 0;
}

/**
 * Validate all encoding parameters
 * @param {Object} params - Object containing all encoding parameters
 * @throws {Error} If any parameter is invalid
 */
function validateParameters(params) {
    const { version, DSCP, ECN, identification, fragmentOffset, ttl, payload } = params;

    if (version !== 4) {
        throw new Error('Only IPv4 (version 4) is supported');
    }

    if (DSCP < 0 || DSCP > 63) {
        throw new Error('DSCP must be 0-63');
    }

    if (ECN < 0 || ECN > 3) {
        throw new Error('ECN must be 0-3');
    }

    if (identification < 0 || identification > 65535) {
        throw new Error('Identification must be 0-65535');
    }

    if (fragmentOffset < 0 || fragmentOffset > 8191) {
        throw new Error('Fragment offset must be 0-8191');
    }

    if (ttl < 0 || ttl > 255) {
        throw new Error('TTL must be 0-255');
    }

    if (!Buffer.isBuffer(payload)) {
        throw new Error('Payload must be a Buffer');
    }
}

module.exports = {
    processOptions,
    processFlagsAndOffset,
    processProtocol,
    onesComplementSum,
    processIP,
    validateParameters
};
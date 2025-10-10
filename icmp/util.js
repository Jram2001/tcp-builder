/**
 * ICMP Type → Rest of Header format map
 * 
 * Each key = ICMP Type (number)
 * Each value = description of how "Rest of Header" should be structured
 * 
 * You can use this object for:
 *  - Validation (warn if type is not recognized)
 *  - Guiding packet construction logic
 */

const ICMP_TYPE_MAP = {
    0: { // Echo Reply
        name: "Echo Reply",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    },

    3: { // Destination Unreachable
        name: "Destination Unreachable",
        restOfHeader: {
            description: "Unused (4 bytes, set to zero)",
            fields: [
                { name: "Unused", size: 4 }
            ]
        }
    },

    4: { // Source Quench (deprecated)
        name: "Source Quench",
        restOfHeader: {
            description: "Unused (4 bytes, set to zero)",
            fields: [
                { name: "Unused", size: 4 }
            ]
        }
    },

    5: { // Redirect Message
        name: "Redirect",
        restOfHeader: {
            description: "Gateway IP address (4 bytes)",
            fields: [
                { name: "Gateway IP", size: 4 }
            ]
        }
    },

    8: { // Echo Request
        name: "Echo Request",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    },

    11: { // Time Exceeded
        name: "Time Exceeded",
        restOfHeader: {
            description: "Unused (4 bytes, set to zero)",
            fields: [
                { name: "Unused", size: 4 }
            ]
        }
    },

    12: { // Parameter Problem
        name: "Parameter Problem",
        restOfHeader: {
            description: "Pointer (1 byte) + Unused (3 bytes)",
            fields: [
                { name: "Pointer", size: 1 },
                { name: "Unused", size: 3 }
            ]
        }
    },

    13: { // Timestamp Request
        name: "Timestamp Request",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    },

    14: { // Timestamp Reply
        name: "Timestamp Reply",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    },

    15: { // Information Request (obsolete)
        name: "Information Request",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    },

    16: { // Information Reply (obsolete)
        name: "Information Reply",
        restOfHeader: {
            description: "Identifier (2 bytes) + Sequence Number (2 bytes)",
            fields: [
                { name: "Identifier", size: 2 },
                { name: "Sequence Number", size: 2 }
            ]
        }
    }
};


/**
 * Helper to validate ICMP type
 */
function validateICMPType(type) {
    if (!ICMP_TYPE_MAP.hasOwnProperty(type)) {
        console.warn(`⚠️ Unknown ICMP Type: ${type} — Rest of Header format undefined.`);
        return null;
    }
    return ICMP_TYPE_MAP[type];
}




/**
 * Validate ICMP Rest of Header
 * @param {number} type - ICMP type (e.g., 8 for Echo Request)
 * @param {Buffer} restOfHeader - Buffer containing the actual Rest of Header
 */
function validateRestOfHeader(type, restOfHeader) {
    const typeInfo = validateICMPType(type);
    if (!typeInfo) return false;

    // Calculate expected length
    const expectedLength = typeInfo.restOfHeader.fields.reduce(
        (sum, field) => sum + field.size,
        0
    );

    if (restOfHeader.length !== expectedLength) {
        console.warn(
            `❌ Invalid Rest of Header length for ICMP Type ${type} (${typeInfo.name}). Expected ${expectedLength} bytes, got ${restOfHeader.length} bytes.`
        );
        return false;
    }

    console.log(`✅ Rest of Header is valid for ICMP Type ${type} (${typeInfo.name})`);
    return true;
}

// Example usage
const icmpType = 8; // Echo Request
const restOfHeader = Buffer.from([0x12, 0x34, 0x00, 0x01]); // Identifier + Sequence Number

validateRestOfHeader(icmpType, restOfHeader);


/**
 * Calculates the ICMP checksum for IPv4.
 *
 * @param {Buffer} icmpMessage - ICMP header + type-specific header + data
 * @returns {number} 16-bit checksum
 */
function calculateIcmpChecksum(icmpMessage) {
    let sum = 0;

    for (let i = 0; i < icmpMessage.length; i += 2) {
        const word = (icmpMessage[i] << 8) + (icmpMessage[i + 1] || 0);
        sum += word;

        // Fold carry bits beyond 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
    }

    return ~sum & 0xFFFF; // One's complement
}

const typeValues = {
    "Echo Reply": {
        value: 0,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    },

    "Destination Unreachable": {
        value: 3,
        generateROH: (mtu = 0) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(0, 0);
            buf.writeUInt16BE(mtu, 2);
            return buf;
        }
    },

    "Source Quench": {
        value: 4,
        generateROH: () => Buffer.alloc(4)
    },

    "Redirect": {
        value: 5,
        generateROH: (gatewayAddr) => {
            const parts = gatewayAddr.split(".").map(Number);
            return Buffer.from(parts);
        }
    },

    "Echo Request": {
        value: 8,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    },

    "Router Advertisement": {
        value: 9,
        generateROH: (numAddresses = 1, entrySize = 2, lifetime = 180, entries = []) => {
            let header = Buffer.alloc(4);
            header.writeUInt8(numAddresses, 0);
            header.writeUInt8(entrySize, 1);
            header.writeUInt16BE(lifetime, 2);

            const entryBufs = entries.map(e => {
                const addr = Buffer.from(e.address.split(".").map(Number));
                const pref = Buffer.alloc(4);
                pref.writeInt32BE(e.preference || 0, 0);
                return Buffer.concat([addr, pref]);
            });

            return Buffer.concat([header, ...entryBufs]);
        }
    },

    "Router Solicitation": {
        value: 10,
        generateROH: () => Buffer.alloc(4) 
    },

    "Time Exceeded": {
        value: 11,
        generateROH: () => Buffer.alloc(4) 
    },

    "Parameter Problem": {
        value: 12,
        generateROH: (pointer = 0) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt8(pointer, 0);
            return buf;
        }
    },

    "Timestamp Request": {
        value: 13,
        generateROH: (identifier, seq, originateTs = 0) => {
            const buf = Buffer.alloc(12);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            buf.writeUInt32BE(originateTs, 4);
            return buf;
        }
    },

    "Timestamp Reply": {
        value: 14,
        generateROH: (identifier, seq, originateTs, receiveTs, transmitTs) => {
            const buf = Buffer.alloc(20);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            buf.writeUInt32BE(originateTs, 4);
            buf.writeUInt32BE(receiveTs, 8);
            buf.writeUInt32BE(transmitTs, 12);
            return buf;
        }
    },

    "Information Request": {
        value: 15,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    },

    "Information Reply": {
        value: 16,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    },

    "Address Mask Request": {
        value: 17,
        generateROH: (identifier, seq, mask = "255.255.255.0") => {
            const buf = Buffer.alloc(8);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            const maskBuf = Buffer.from(mask.split(".").map(Number));
            maskBuf.copy(buf, 4);
            return buf;
        }
    },

    "Address Mask Reply": {
        value: 18,
        generateROH: (identifier, seq, mask = "255.255.255.0") => {
            const buf = Buffer.alloc(8);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            const maskBuf = Buffer.from(mask.split(".").map(Number));
            maskBuf.copy(buf, 4);
            return buf;
        }
    },

    "Traceroute": {
        value: 30,
        generateROH: (id = 0, outHop = 0, retHop = 0, linkSpeed = 0, linkMTU = 0) => {
            const buf = Buffer.alloc(12);
            buf.writeUInt16BE(id, 0);
            buf.writeUInt16BE(outHop, 2);
            buf.writeUInt16BE(retHop, 4);
            buf.writeUInt32BE(linkSpeed, 6);
            buf.writeUInt32BE(linkMTU, 10);
            return buf;
        }
    },

    "Extended Echo Request": {
        value: 42,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    },

    "Extended Echo Reply": {
        value: 43,
        generateROH: (identifier, seq) => {
            const buf = Buffer.alloc(4);
            buf.writeUInt16BE(identifier, 0);
            buf.writeUInt16BE(seq, 2);
            return buf;
        }
    }
};


module.exports = {
    ICMP_TYPE_MAP,
    validateICMPType,
    validateRestOfHeader,
    calculateIcmpChecksum
};


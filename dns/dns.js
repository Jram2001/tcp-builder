const {
    checkAndRead16,
    checkAndWrite16,
    checkAndRead8,
    checkAndWrite8
} = require("../util");

/**
 * DNS Packet Builder - Main API
 * High-level interface for DNS operations
 */

const { encodeDomainName, parseFlags, encodeFlags } = require('./utils');
const { DNS_TYPES, DNS_CLASSES } = require('./constants');

/**
 * DNS Header Encoder - Builds RFC 1035 compliant DNS header
 * Creates 12-byte DNS header with transaction ID, flags, and section counts
 */
function Encode(transactionId, flags, QDcount = 1, ANcount = 0, NScount = 0, AScount = 0) {
    const packet = Buffer.alloc(12);
    checkAndWrite16(packet, transactionId, 0);
    checkAndWrite16(packet, encodeFlags(flags), 2);
    checkAndWrite16(packet, QDcount, 4);
    checkAndWrite16(packet, ANcount, 6);
    checkAndWrite16(packet, NScount, 8);
    checkAndWrite16(packet, AScount, 10);
    return packet;
}

/**
 * DNS Header Decoder - Parses DNS header from packet
 * Extracts transaction ID, flags, and section counts from 12-byte header
 */
function Decode(packet) {
    if (packet.length < 12) {
        console.warn("Potentially malformed packet: DNS PAcket must be less that 12 bytes long")
    };

    return {
        transactionId: checkAndRead16(packet, 0),
        flags: parseFlags(checkAndRead16(packet, 2)),
        questionCount: checkAndRead16(packet, 4),
        answerCount: checkAndRead16(packet, 6),
        authorityCount: checkAndRead16(packet, 8),
        additionalCount: checkAndRead16(packet, 10)
    };

}

// Build question section
function buildQuestion(domain, type, cls = DNS_CLASSES.IN) {
    const encodedName = encodeDomainName(domain);
    const typeBuffer = Buffer.alloc(2);
    const classBuffer = Buffer.alloc(2);

    checkAndWrite16(typeBuffer, type, 0);
    checkAndWrite16(classBuffer, cls, 0);

    return Buffer.concat([encodedName, typeBuffer, classBuffer]);
}

/**
 * Complete DNS Query Builder - User-friendly wrapper
 * Builds complete DNS query packet ready to send
 */
function CreateDNSQuery(questions, options = {}) {
    const questionBuffers = questions.map(q =>
        buildQuestion(q.domain, q.type, q.class)
    );

    const transactionId = options.transactionId || Math.floor(Math.random() * 65536);
    const flags = options.flags || { qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, z: 0, rcode: 0 };

    const header = Encode(transactionId, flags, questions.length, 0, 0, 0);

    return Buffer.concat([header, ...questionBuffers]);
}

module.exports = {
    Encode,
    Decode,
    CreateDNSQuery,
    buildQuestion,
    DNS_TYPES,
    DNS_CLASSES
};

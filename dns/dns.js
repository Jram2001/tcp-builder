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
    packet.writeUInt16BE(transactionId, 0);
    packet.writeUInt16BE(encodeFlags(flags), 2);
    packet.writeUInt16BE(QDcount, 4);
    packet.writeUInt16BE(ANcount, 6);
    packet.writeUInt16BE(NScount, 8);
    packet.writeUInt16BE(AScount, 10);
    return packet;
}

/**
 * DNS Header Decoder - Parses DNS header from packet
 * Extracts transaction ID, flags, and section counts from 12-byte header
 */
function Decode(packet) {
    return {
        transactionId: packet.readUInt16BE(0),
        flags: parseFlags(packet.readUInt16BE(2)),
        questionCount: packet.readUInt16BE(4),
        answerCount: packet.readUInt16BE(6),
        authorityCount: packet.readUInt16BE(8),
        additionalCount: packet.readUInt16BE(10)
    };
}

// Build question section
function buildQuestion(domain, type, cls = DNS_CLASSES.IN) {
    const encodedName = encodeDomainName(domain);
    const typeBuffer = Buffer.alloc(2);
    const classBuffer = Buffer.alloc(2);

    typeBuffer.writeUInt16BE(type, 0);
    classBuffer.writeUInt16BE(cls, 0);

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

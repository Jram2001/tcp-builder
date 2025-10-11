/**
 * DNS Protocol Utilities
 * Low-level encoding/decoding functions
 */

// Encode domain name into DNS wire format
function encodeDomainName(name) {
    if (name === '.') return Buffer.from([0]); // Root domain

    const result = [];
    name.split('.').forEach(label => {
        if (label.length > 63) throw new Error('Label too long');
        result.push(label.length);
        for (const ch of label) result.push(ch.charCodeAt(0));
    });
    result.push(0);
    return Buffer.from(result);
}

// Extract flags from 16-bit field
function parseFlags(flagsField) {
    return {
        qr: (flagsField >> 15) & 0x1,
        opcode: (flagsField >> 11) & 0xF,
        aa: (flagsField >> 10) & 0x1,
        tc: (flagsField >> 9) & 0x1,
        rd: (flagsField >> 8) & 0x1,
        ra: (flagsField >> 7) & 0x1,
        z: (flagsField >> 4) & 0x7,
        rcode: flagsField & 0xF
    };
}

// Combine flags into 16-bit field
function encodeFlags(flags) {
    return (flags.qr << 15) |
        (flags.opcode << 11) |
        (flags.aa << 10) |
        (flags.tc << 9) |
        (flags.rd << 8) |
        (flags.ra << 7) |
        (flags.z << 4) |
        flags.rcode;
}

module.exports = { encodeDomainName, parseFlags, encodeFlags };

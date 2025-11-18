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

    const qr = (field >>> 15) & 0x1;
    const opcode = (field >>> 11) & 0xF;
    const aa = (field >>> 10) & 0x1;
    const tc = (field >>> 9) & 0x1;
    const rd = (field >>> 8) & 0x1;
    const ra = (field >>> 7) & 0x1;
    const z = (field >>> 4) & 0x7;   // 3 reserved bits
    const rcode = field & 0xF;

    if (z != 0) {
        console.log("Potentially malformed packet : Reserved bit must always be zeor");
    }
    if (opcode > 5) {
        console.log("Potentially malformed packet : Opcode mist be less than 6");
    }
    if (rcode > 15) {
        console.log("Potentially malformed packet : querry response mist be less than 6");
    }
    return {
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode
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

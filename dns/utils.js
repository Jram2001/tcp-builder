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

    const qr = (flagsField >>> 15) & 0x1;
    const opcode = (flagsField >>> 11) & 0xF;
    const aa = (flagsField >>> 10) & 0x1;
    const tc = (flagsField >>> 9) & 0x1;
    const rd = (flagsField >>> 8) & 0x1;
    const ra = (flagsField >>> 7) & 0x1;
    const z = (flagsField >>> 4) & 0x7;   // 3 reserved bits
    const rcode = flagsField & 0xF;

    if (z != 0) {
        console.warn("Potentially malformed packet : Reserved bit must always be zeor");
    }
    if (opcode > 5) {
        console.warn("Potentially malformed packet : Opcode mist be less than 6");
    }
    if (rcode > 15) {
        console.warn("Potentially malformed packet : querry response mist be less than 6");
    }

    if (qr && ra) {
        console.warn("Weired flag combination found")
    }

    if (qr && aa) {
        console.warn("Weired flag combination found")
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

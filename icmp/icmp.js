const { validateRestOfHeader, calculateIcmpChecksum } = require('./util')

/**
 * Encodes an ICMP message (e.g., Echo Request/Reply) into a Buffer.
 * Handles Type, Code, Identifier, Sequence Number, optional data, and calculates checksum.
 *
 * @param {number} type - ICMP type (e.g., 8 for Echo Request)
 * @param {number} code - ICMP code (usually 0 for Echo)
 * @param {number} identifier - 2-byte identifier (default 0)
 * @param {number} sequence - 2-byte sequence number (default 0)
 * @param {Buffer} data - Optional payload data
 * @returns {Buffer} - Complete ICMP message ready for transmission
 */
function EncodeRAW(type, code, identifier = 0, sequence = 0, data = Buffer.alloc(0)) {
    const header = Buffer.alloc(8 + data.length);

    header[0] = type;
    header[1] = code;
    header.writeUInt16BE(0, 2); // Initialize checksum to 0
    header.writeUInt16BE(identifier, 4);
    header.writeUInt16BE(sequence, 6);

    if (data.length > 0) data.copy(header, 8);

    header.writeUInt16BE(calculateIcmpChecksum(header), 2); // Fill checksum

    return header;
}

/**
 * Decodes an ICMP packet Buffer into a readable object.
 *
 * @param {Buffer} packet - Raw ICMP message
 * @returns {Object} - Parsed ICMP fields
 */
function Decode(packet) {
    const output = {};

    output.type = packet[0];
    output.code = packet[1];
    output.checksum = packet.readUInt16BE(2);
    output.identifier = packet.readUInt16BE(4);
    output.sequence = packet.readUInt16BE(6);
    output.data = packet.slice(8); // Remaining payload

    return output;
}

function Encode(type , code){

}

module.exports = { Encode, Decode };

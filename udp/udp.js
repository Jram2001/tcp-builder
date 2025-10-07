const { buildPseudoHeader, calculateChecksum } = require('./util')

/**
 * Encodes a UDP packet with the given source/destination IPs and ports, 
 * along with optional payload data.
 * 
 * @param {string} srcIp - Source IP address (used for checksum calculation)
 * @param {string} destIp - Destination IP address (used for checksum calculation)
 * @param {number} srcPort - Source port number (0-65535)
 * @param {number} destPort - Destination port number (0-65535)
 * @param {Buffer} [data=Buffer.alloc(0)] - Optional payload data
 * @returns {Buffer} The complete UDP packet ready to be sent
 */
function Encode(srcIp, destIp, srcPort, destPort, data = Buffer.alloc(0)) {

    // Allocate 8-byte UDP header
    const header = Buffer.alloc(8);

    // Fill UDP header fields: Source Port, Destination Port, Length
    header.writeUInt16BE(srcPort, 0);
    header.writeUInt16BE(destPort, 2);
    header.writeUInt16BE(8 + data.length, 4);

    // Build pseudo-header for checksum and calculate UDP checksum
    const psuedoHeader = buildPseudoHeader(srcIp, destIp, 8 + data.length);
    const checkSum = calculateChecksum(psuedoHeader, header, data);

    // Write checksum to header
    header.writeUInt16BE(checkSum, 6);

    // Combine header and payload
    return Buffer.concat([header, data]);
}

/**
 * Decodes a UDP packet and extracts header fields and payload.
 * Optionally skips the IP header if the packet includes it.
 * 
 * @param {Buffer} udpPacket - The UDP packet (with or without IP header)
 * @param {boolean} [skipIPHeader=false] - Whether to skip the first 20 bytes (IP header)
 * @returns {Object} An object containing:
 *   - sourcePort: Number
 *   - destinationPort: Number
 *   - length: Number
 *   - checksum: Number
 *   - data: Buffer (payload)
 */
function Decode(udpPacket, skipIPHeader = false) {
    let output = {};

    // Determine starting point of UDP header
    let udpStart = skipIPHeader ? 20 : 0;

    // Extract UDP header fields
    output['SourcePort'] = udpPacket.readUInt16BE(udpStart + 0);
    output['destinationPort'] = udpPacket.readUInt16BE(udpStart + 2);
    output['length'] = udpPacket.readUInt16BE(udpStart + 4);
    output['checksum'] = udpPacket.readUInt16BE(udpStart + 6);

    // Extract payload data
    output['data'] = udpPacket.slice(udpStart + 8);

    return output;
}



module.exports = {
    Encode,
    Decode,
    psuedoHeader: buildPseudoHeader,
    checksum: calculateChecksum
};

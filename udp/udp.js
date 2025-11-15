const { buildPseudoHeader, calculateChecksum } = require('./util');

/**
 * Encodes a UDP packet with the given source/destination IPs and ports.
 * 
 * @param {string} srcIp - Source IP address
 * @param {string} destIp - Destination IP address
 * @param {number} srcPort - Source port (0-65535)
 * @param {number} destPort - Destination port (0-65535)
 * @param {Buffer} [data=Buffer.alloc(0)] - Payload data
 * @returns {Buffer} Complete UDP packet
 */
function Encode(srcIp, destIp, srcPort, destPort, data = Buffer.alloc(0)) {
    const header = Buffer.alloc(8);

    header.writeUInt16BE(srcPort, 0);
    header.writeUInt16BE(destPort, 2);
    header.writeUInt16BE(8 + data.length, 4);

    if (data.length % 2 !== 0) {
        console.warn(
            `[UDP Security] Odd-length payload (${data.length} bytes) may leak memory when sent via raw sockets. ` +
            `Consider padding to even length.`
        );
    }

    const pseudoHeader = buildPseudoHeader(srcIp, destIp, 8 + data.length);
    const checksum = calculateChecksum(pseudoHeader, header, data);
    header.writeUInt16BE(checksum, 6);

    return Buffer.concat([header, data]);
}

/**
 * Decodes a UDP packet and extracts header fields and payload.
 * 
 * @param {Buffer} udpPacket - UDP packet buffer
 * @param {boolean} [skipIPHeader=false] - Skip first 20 bytes (IP header)
 * @returns {Object|null} Decoded packet or null if invalid
 */
function Decode(udpPacket, skipIPHeader = false) {
    const output = {};
    const udpStart = skipIPHeader ? 20 : 0;
    const availableBytes = udpPacket.length - udpStart;

    if (availableBytes < 8) {
        console.warn(
            `[UDP Decode] Packet too small: need 8 bytes for header, got ${availableBytes} bytes.`
        );
        return null;
    }

    output['SourcePort'] = udpPacket.readUInt16BE(udpStart);
    output['destinationPort'] = udpPacket.readUInt16BE(udpStart + 2);
    output['length'] = udpPacket.readUInt16BE(udpStart + 4);
    output['checksum'] = udpPacket.readUInt16BE(udpStart + 6);

    if (availableBytes < output['length']) {
        console.warn(
            `[UDP Decode] Packet truncated: expected ${output['length']} bytes, got ${availableBytes} bytes.`
        );
    }

    output['data'] = udpPacket.slice(udpStart + 8, udpStart + output['length']);
    return output;
}

module.exports = {
    Encode,
    Decode,
    pseudoHeader: buildPseudoHeader,
    checksum: calculateChecksum
};
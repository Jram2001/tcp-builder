const { buildPseudoHeader, calculateChecksum, isValidIP } = require('./util');
const ipv4 = require('../ipv4/ipv4');
const {
    checkAndRead16,
    checkAndWrite16
} = require("../util");

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

    if (!isValidIP(srcIp)) {
        console.warn("Not a vaild source IP Address")
    }

    if (!isValidIP(destIp)) {
        console.warn("Not a vaild destination IP Address")
    }

    if (parseInt(srcPort) > 65535 || parseInt(destPort) > 65535) {
        console.warn("Noat a valid source or destination port")
    }

    const header = Buffer.alloc(8);

    checkAndWrite16(header, srcPort, 0);
    checkAndWrite16(header, destPort, 2);
    checkAndWrite16(header, 8 + data.length, 4);

    if (data.length % 2 !== 0) {
        console.warn(
            `[UDP Security] Odd-length payload (${data.length} bytes) may leak memory when sent via raw sockets. ` +
            `Consider padding to even length.`
        );
    }

    const pseudoHeader = buildPseudoHeader(srcIp, destIp, 8 + data.length);
    const checksum = calculateChecksum(pseudoHeader, header, data);
    checkAndWrite16(header, checksum, 6);

    return Buffer.concat([header, data]);
}

/**
 * Decodes a UDP packet and extracts header fields and payload.
 * * @param {Buffer} udpPacket - UDP packet buffer
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

    output['SourcePort'] = checkAndRead16(udpPacket, udpStart);
    output['destinationPort'] = checkAndRead16(udpPacket, udpStart + 2);
    output['length'] = checkAndRead16(udpPacket, udpStart + 4);
    output['checksum'] = checkAndRead16(udpPacket, udpStart + 6);

    const declaredPayloadLength = output['length'] - 8;
    const availablePayloadLength = availableBytes - 8;

    const actualDataLength = Math.min(declaredPayloadLength, availablePayloadLength);

    if (availableBytes < output['length']) {
        console.warn(
            `[UDP Decode] Packet truncated: expected ${output['length']} bytes, got ${availableBytes} bytes. ` +
            `Processing only ${actualDataLength} bytes of data.`
        );
    }


    const data = udpPacket.slice(udpStart + 8, udpStart + 8 + actualDataLength);
    output['data'] = data;

    if (udpStart) {
        try {
            const header = udpPacket.slice(udpStart, udpStart + 8);
            const headerForChecksum = Buffer.from(header);
            checkAndWrite16(headerForChecksum, 0, 6);
            const ipData = ipv4.Decode(udpPacket);
            const pseudoHeader = buildPseudoHeader(ipData.srcIp, ipData.destIp, output['length']);
            const calculatedChecksum = calculateChecksum(pseudoHeader, headerForChecksum, data);
            if (calculatedChecksum !== output.checksum) {
                console.warn(
                    `[UDP Decode] 🚨 Checksum Mismatch! Calculated ${calculatedChecksum}, Received ${output.checksum}. ` +
                    `Data integrity is compromised.`
                );
            }
        } catch (error) {
            console.warn("Error while parsing udp checksum", error);
        }
    }


    return output;
}
module.exports = {
    Encode,
    Decode,
    pseudoHeader: buildPseudoHeader,
    checksum: calculateChecksum
};
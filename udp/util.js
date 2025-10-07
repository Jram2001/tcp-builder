/**
 * Builds the pseudo-header required for UDP checksum calculation.
 * The pseudo-header is not transmitted, but it is included in the checksum
 * to cover IP-layer information (source IP, destination IP, protocol, length).
 *
 * @param {string} srcIP - Source IP in dotted decimal format (e.g., "192.168.1.1")
 * @param {string} destIP - Destination IP in dotted decimal format
 * @param {number} udpLength - Length of UDP header + payload in bytes
 * @returns {Buffer} 12-byte pseudo-header
 */
function buildPseudoHeader(srcIP, destIP, udpLength) {
    const pseudoHeader = Buffer.alloc(12);

    // Copy source IP (first 4 bytes)
    srcIP.split('.').forEach((octet, i) => {
        pseudoHeader[i] = parseInt(octet, 10);
    });

    // Copy destination IP (next 4 bytes)
    destIP.split('.').forEach((octet, i) => {
        pseudoHeader[i + 4] = parseInt(octet, 10);
    });

    pseudoHeader[8] = 0;      // Reserved byte
    pseudoHeader[9] = 17;     // Protocol number for UDP
    pseudoHeader.writeUInt16BE(udpLength, 10); // UDP length in big-endian

    return pseudoHeader;
}

/**
 * Calculates the UDP checksum using the pseudo-header, UDP header, and payload.
 * Implements the standard 16-bit one's complement Internet checksum algorithm.
 *
 * @param {Buffer} pseudoHeader - 12-byte pseudo-header
 * @param {Buffer} udpHeader - 8-byte UDP header
 * @param {Buffer} data - UDP payload
 * @returns {number} 16-bit checksum
 */
function calculateChecksum(pseudoHeader, udpHeader, data) {
    const total = Buffer.concat([pseudoHeader, udpHeader, data]);
    let sum = 0;

    // Iterate over each 16-bit word in the buffer
    for (let i = 0; i < total.length; i += 2) {
        const word = (total[i] << 8) + (total[i + 1] || 0);
        sum += word;

        // Fold carry bits beyond 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
    }

    return ~sum & 0xFFFF; // One's complement, 16-bit checksum
}

module.exports = { buildPseudoHeader, calculateChecksum };

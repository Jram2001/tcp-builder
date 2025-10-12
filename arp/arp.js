
const { readMAC, readIP, processIP, processMAC } = require('./utils')

// ┌─────────────────────────────────────────┐
// │  Hardware Type (2 bytes) - Ethernet=1   │
// ├─────────────────────────────────────────┤
// │  Protocol Type (2 bytes) - IPv4=0x0800  │
// ├─────────────────────────────────────────┤
// │  Hardware Length (1 byte) - MAC=6       │
// ├─────────────────────────────────────────┤
// │  Protocol Length (1 byte) - IPv4=4      │
// ├─────────────────────────────────────────┤
// │  Operation (2 bytes) - Request=1/Reply=2│
// ├─────────────────────────────────────────┤
// │  Sender Hardware Address (6 bytes)      │
// ├─────────────────────────────────────────┤
// │  Sender Protocol Address (4 bytes)      │
// ├─────────────────────────────────────────┤
// │  Target Hardware Address (6 bytes)      │
// ├─────────────────────────────────────────┤
// │  Target Protocol Address (4 bytes)      │
// └─────────────────────────────────────────┘

/**
 * Encodes an ARP packet.
 * @param {number} hType - Hardware Type (2 bytes, e.g., 1 for Ethernet)
 * @param {number} pType - Protocol Type (2 bytes, e.g., 0x0800 for IPv4)
 * @param {number} hLen - Hardware Address length in bytes (usually 6)
 * @param {number} pLen - Protocol Address length in bytes (usually 4)
 * @param {number} oper - Operation (1=request, 2=reply)
 * @param {Buffer} senderHwAddr - Sender MAC address
 * @param {Buffer} senderProtoAddr - Sender IP address
 * @param {Buffer} targetHwAddr - Target MAC address
 * @param {Buffer} targetProtoAddr - Target IP address
 * @returns {Buffer} Encoded ARP packet
 */
function Encode(hType, pType, hLen, pLen, oper, senderHwAddr, senderProtoAddr, targetHwAddr, targetProtoAddr) {
    const packet = Buffer.alloc(28);
    packet.writeUInt16BE(hType, 0);
    packet.writeUInt16BE(pType, 2);
    packet.writeUInt8(hLen, 4);
    packet.writeUInt8(pLen, 5);
    packet.writeUInt16BE(oper, 6);

    // Convert and copy addresses
    const senderMAC = processMAC(senderHwAddr);
    const senderIP = processIP(senderProtoAddr);
    const targetMAC = processMAC(targetHwAddr);
    const targetIP = processIP(targetProtoAddr);

    senderMAC.copy(packet, 8)
    senderIP.copy(packet, 14)
    targetMAC.copy(packet, 18)
    targetIP.copy(packet, 24)

    console.log(packet);
    return packet;
}



/**
 * Decodes an ARP packet.
 * @param {Buffer} packet - ARP packet buffer (28 bytes)
 * @returns {Object} Decoded ARP packet with all fields
 */
function Decode(packet) {
    const output = {};
    output['hType'] = packet.readUInt16BE(0);
    output['pType'] = packet.readUInt16BE(2);
    output['hLen'] = packet.readUInt8(4);
    output['pLen'] = packet.readUInt8(5);
    output['oper'] = packet.readUInt16BE(6);

    output['senderMAC'] = readMAC(packet.subarray(8, 14));
    output['senderIP'] = readIP(packet.subarray(14, 18));
    output['targetMAC'] = readMAC(packet.subarray(18, 24));
    output['targetIP'] = readIP(packet.subarray(24, 28));

    return output;
}

module.exports = { Encode, Decode }
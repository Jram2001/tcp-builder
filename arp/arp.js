
const { readMAC, readIP, processIP, processMAC, isValidIP } = require('./utils')
const {
    checkAndRead16,
    checkAndWrite16,
    checkAndRead8,
    checkAndWrite8,

} = require("../util");

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
 * @param {string} senderHwAddr - Sender MAC address
 * @param {string} senderProtoAddr - Sender IP address
 * @param {string} targetHwAddr - Target MAC address
 * @param {string} targetProtoAddr - Target IP address
 * @returns {Buffer} Encoded ARP packet
 */
function Encode(hType, pType, hLen, pLen, oper, senderHwAddr, senderProtoAddr, targetHwAddr, targetProtoAddr) {

    const valid =
        hType == 0x0001 &&
        pType == 0x0800 &&
        hLen == 6 &&
        pLen == 4;

    if (!valid) {
        console.warn("[ARP] Only Ethernet (HTYPE=1, HLEN=6) + IPv4 (PTYPE=0x0800, PLEN=4) supported");
    }

    if (!isValidIP(senderProtoAddr) || !isValidIP(targetProtoAddr)) {
        console.warn("[ARP] Invalid IPv4 address");
    }

    const macRegex = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

    if (!macRegex.test(senderHwAddr) || !macRegex.test(targetHwAddr)) {
        console.warn("[ARP] Invalid MAC address format");
    }

    if (oper !== 1 && oper !== 2) {
        console.warn("[ARP] Invalid ARP opcode (must be 1=request or 2=reply)");
    }

    const packet = Buffer.alloc(28);
    checkAndWrite16(packet, hType, 0);
    checkAndWrite16(packet, pType, 2);
    checkAndWrite8(packet, hLen, 4);
    checkAndWrite8(packet, pLen, 5);
    checkAndWrite16(packet, oper, 6);

    // Convert and copy addresses
    const senderMAC = processMAC(senderHwAddr);
    const senderIP = processIP(senderProtoAddr);
    const targetMAC = processMAC(targetHwAddr);
    const targetIP = processIP(targetProtoAddr);

    if (senderMAC.length !== 6 || targetMAC.length !== 6) {
        console.warn("[ARP] Invalid MAC address (must be exactly 6 bytes)");
    }

    senderMAC.copy(packet, 8);
    senderIP.copy(packet, 14);
    targetMAC.copy(packet, 18);
    targetIP.copy(packet, 24);

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

    // -------------------------
    // Basic length validation
    // -------------------------
    if (!Buffer.isBuffer(packet)) {
        throw new Error("[ARP] Decode error: input must be a Buffer");
    }

    if (packet.length !== 28) {
        console.warn(`[ARP] Invalid ARP packet length: ${packet.length} bytes (expected 28)`);
    }

    // -------------------------
    // Extract header fields
    // -------------------------
    const hType = checkAndRead16(packet, 0);
    const pType = checkAndRead16(packet, 2);
    const hLen = checkAndRead8(packet, 4);
    const pLen = checkAndRead8(packet, 5);
    const oper = checkAndRead16(packet, 6);

    output.hType = hType;
    output.pType = pType;
    output.hLen = hLen;
    output.pLen = pLen;
    output.oper = oper;

    // -------------------------
    // Validate ARP/Ethernet/IP header
    // -------------------------
    const arpValid =
        hType === 0x0001 &&
        pType === 0x0800 &&
        hLen === 6 &&
        pLen === 4;

    if (!arpValid) {
        console.warn("[ARP] Warning: Non-standard ARP header detected");
        console.warn(`HTYPE=${hType}, PTYPE=${pType}, HLEN=${hLen}, PLEN=${pLen}`);
    }

    // -------------------------
    // Operation validation
    // -------------------------
    if (oper !== 1 && oper !== 2) {
        console.warn(`[ARP] Invalid opcode: ${oper} (must be 1=request or 2=reply)`);
    }

    // -------------------------
    // Extract raw address bytes
    // -------------------------
    const senderMACbuf = packet.subarray(8, 14);
    const senderIPbuf = packet.subarray(14, 18);
    const targetMACbuf = packet.subarray(18, 24);
    const targetIPbuf = packet.subarray(24, 28);

    // -------------------------
    // Validate MAC binary size
    // -------------------------
    if (senderMACbuf.length !== 6 || targetMACbuf.length !== 6) {
        console.warn("[ARP] Invalid MAC address length (must be exactly 6 bytes)");
    }

    // -------------------------
    // Validate IP binary size
    // -------------------------
    if (senderIPbuf.length !== 4 || targetIPbuf.length !== 4) {
        console.warn("[ARP] Invalid IPv4 address length (must be exactly 4 bytes)");
    }

    // -------------------------
    // Convert to readable format
    // -------------------------
    const senderMAC = readMAC(senderMACbuf);
    const senderIP = readIP(senderIPbuf);
    const targetMAC = readMAC(targetMACbuf);
    const targetIP = readIP(targetIPbuf);

    // -------------------------
    // Validate printable MAC / IP values
    // -------------------------
    const macRegex = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

    if (!macRegex.test(senderMAC) || !macRegex.test(targetMAC)) {
        console.warn("[ARP] Invalid decoded MAC address format");
    }

    if (!isValidIP(senderIP) || !isValidIP(targetIP)) {
        console.warn("[ARP] Invalid decoded IPv4 address");
    }

    // -------------------------
    // Save readable outputs
    // -------------------------
    output.senderMAC = senderMAC;
    output.senderIP = senderIP;
    output.targetMAC = targetMAC;
    output.targetIP = targetIP;

    return output;
}


module.exports = { Encode, Decode }
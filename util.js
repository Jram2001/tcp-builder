/**
 * Safely read a big-endian 16-bit unsigned integer from a buffer.
 * @param {Buffer} buffer - Buffer to read from
 * @param {number} [from=0] - Byte offset at which the 16-bit value starts
 * @returns {number|null} The unsigned 16-bit value, or `null` if the buffer
 *                        is too short or not a Buffer (logged as warning).
 */
function checkAndRead16(buffer, from = 0) {
    if (!Buffer.isBuffer(buffer)) {
        console.warn('Packet must be a Buffer');
        return 0;
    }
    if (buffer.length < from + 2) {
        console.warn('Buffer too short for 16-bit field');
        return 0;
    }
    return buffer.readUInt16BE(from);
}

/**
 * Safely read a big-endian 8-bit unsigned integer from a buffer.
 * @param {Buffer} buffer - Buffer to read from
 * @param {number} [from=0] - Byte offset at which the 8-bit value starts
 * @returns {number|null} The unsigned 8-bit value, or `null` if the buffer
 *                        is too short or not a Buffer (logged as warning).
 */
function checkAndRead8(buffer, from = 0) {
    if (!Buffer.isBuffer(buffer)) {
        console.warn('Packet must be a Buffer');
        return 0;
    }
    if (buffer.length < from + 1) {
        console.warn('Buffer too short for 8-bit field');
        return 0;
    }
    return buffer.readUInt8(from);
}


/**
 * Safely write a big-endian 16-bit unsigned integer to a buffer.
 * @param {Buffer} buffer - Buffer to write into
 * @param {number} value  - 16-bit unsigned value to write
 * @param {number} [from=0] - Byte offset at which to write
 * @returns {number} 2 on success, 0 on failure (logged)
 */
function checkAndWrite16(buffer, value, from = 0) {
    if (!Buffer.isBuffer(buffer)) {
        console.warn('Packet must be a Buffer');
        return 0;
    }
    if (buffer.length < from + 2) {
        console.warn('Buffer too short for 16-bit field');
        return 0;
    }
    if (value < 0 || value > 0xFFFF || !Number.isInteger(value)) {
        console.warn('Value out of 16-bit unsigned range');
        return 0;
    }
    buffer.writeUInt16BE(value, from);
    return 2; // bytes written
}

/**
 * Safely write an 8-bit unsigned integer to a buffer.
 * @param {Buffer} buffer - Buffer to write into
 * @param {number} value  - 8-bit unsigned value to write
 * @param {number} [from=0] - Byte offset at which to write
 * @returns {number} 1 on success, 0 on failure (logged)
 */
function checkAndWrite8(buffer, value, from = 0) {
    if (!Buffer.isBuffer(buffer)) {
        console.warn('Packet must be a Buffer');
        return 0;
    }
    if (buffer.length < from + 1) {
        console.warn('Buffer too short for 8-bit field');
        return 0;
    }
    if (value < 0 || value > 0xFF || !Number.isInteger(value)) {
        console.warn('Value out of 8-bit unsigned range');
        return 0;
    }
    buffer.writeUInt8(value, from);
    return 1; // bytes written
}

module.exports = {
    checkAndRead16,
    checkAndWrite16,
    checkAndRead8,
    checkAndWrite8
};
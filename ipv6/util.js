function expandIPv6(ip) {
    const parts = ip.split("::");
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - (left.length + right.length);

    let fullAddress = [
        ...left.map(b => b.padStart(4, "0")),
        ...Array(missing).fill("0000"),
        ...right.map(b => b.padStart(4, "0")),
    ];

    let buffer = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
        let hexValue = parseInt(fullAddress[i], 16);
        buffer.writeUInt16BE(hexValue, i * 2);
    }

    return buffer;
}

function bufferToIP(buffer) {
    const groups = [];
    for (let i = 0; i < 8; i++) {
        const value = buffer.readUInt16BE(i * 2);
        groups.push(value.toString(16));
    }
    return groups.join(':');
}

module.exports = { expandIPv6, bufferToIP }
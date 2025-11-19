function readMAC(buf) {
    return Array.from(buf).map(b => { return b.toString(16).padStart(2, '0').toUpperCase() }).join(':')
}

function readIP(buf) {
    return buf.join('.')
}


function processMAC(mac) {
    const bytes = mac.split(':').map(x => parseInt(x, 16));
    return Buffer.from(bytes);
}

function processIP(ip) {
    const bytes = ip.split('.').map(x => parseInt(x, 10));
    return Buffer.from(bytes);
}

/**
 * Validates IPv4 address format
 * @param {string} ipAddress - IP address string
 * @returns {boolean} True if valid IPv4 address
 */
function isValidIP(ipAddress) {
    const octets = ipAddress.split('.').map(n => parseInt(n, 10));

    if (octets.length !== 4) {
        return false;
    }

    return octets.every(n => !Number.isNaN(n) && n >= 0 && n <= 255);
}

module.exports = { readMAC, readIP, processIP, processMAC, isValidIP };
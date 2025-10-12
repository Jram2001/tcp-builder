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

module.exports = { readMAC, readIP, processIP, processMAC };
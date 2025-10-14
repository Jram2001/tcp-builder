function Encode(srcIp, destIp, version, DSCP, ECN, identification, IPFlags, fragmentOffset, ttl, protocol, userOptions) {

    let packet = Buffer.alloc(20);
    let options = Buffer.from(processOptions(userOptions));

    packet.writeUInt8(version << 4 | options.length & 0xff);
    packet.writeUInt8((DSCP << 2 | ECN), 1);

}

function processOptions(options) {
    const ipOptions = {
        EOL: 0,          // End of Option List
        NOP: 1,          // No Operation
        Security: 2,     // Security classification
        LSRR: 131,       // Loose Source and Record Route
        SSRR: 137,       // Strict Source and Record Route
        RR: 7,           // Record Route
        TS: 68           // Timestamp
    };

    return options.map(option => {
        if (!(option in ipOptions)) throw new Error(`Invalid option: ${option}`);
        return ipOptions[option];
    });

}
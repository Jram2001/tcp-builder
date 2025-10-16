function Encode(srcIP, destIP, DSCP, ECN, payload, flowNumber, nextHeader, hopLimit) {

    let header = Buffer.alloc(40);

    let version = 0b0110;
    let traffic = (DSCP << 2) | ECN, 1;
    let totalLength = 40 + payload.length;
    let sourceIP = processIP(srcIP);
    let destnationIP = processIP(destIP);

    let firstWord = (version << 28) | (traffic << 20) | (flowNumber & 0xFFFFF);
    header.writeUInt32BE(firstWord, 0);

    let secondWord = (totalLength << 12) | (nextHeader << 8) | (hopLimit);
    header.writeUInt32BE(secondWord, 4);
    header.writeUInt32BE(sourceIP, 8);
    header.writeUInt32BE(destnationIP, 12);

    return Buffer.concat([header | payload]);
}


function processIP(ip) {
    return ip.split('.').map(data => parseInt(10));
}
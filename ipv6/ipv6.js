const { expandIPv6, bufferToIP } = require('./util');

function Encode(sourceIP, destnationIP, DSCP, ECN, payload, flowNumber, nextHeader, hopLimit) {

    let header = Buffer.alloc(40);

    let version = 0b0110;
    let traffic = (DSCP << 2) | ECN;

    let firstWord = (version << 28) | (traffic << 20) | (flowNumber & 0xFFFFF);
    header.writeUInt32BE(firstWord, 0);

    header.writeUInt16BE(payload.length, 4);
    header.writeUInt8(nextHeader, 6);
    header.writeUInt8(hopLimit, 7);

    expandIPv6(sourceIP).copy(header, 8);
    expandIPv6(destnationIP).copy(header, 24);
    return Buffer.concat([header, payload]);
}

function Decode(packet) {
    let version = {
        0b0100: 'ipv4',
        0b0110: 'ipv6',
    }

    let output = {};

    let firstWord = packet.readUInt32BE(0);
    let Traffic = (firstWord >> 20) & 0xFF;

    output['Version'] = version[(firstWord >> 28)];
    output['DSCP'] = (Traffic >> 2) & 0x3F;
    output['ECN'] = (Traffic) & 0x03;
    output['flowLabel'] = firstWord & 0xFFFFF;
    output['payloadLength'] = packet.readUInt16BE(4);
    output['nextHeader'] = packet.readUInt8(6);
    output['hopLimit'] = packet.readUInt8(7);
    output['sourceAddr'] = bufferToIP(packet.slice(8, 24));
    output['destinationAddr'] = bufferToIP(packet.slice(24, 40));
    output['payload'] = packet.slice(40);

    return output;
}

module.exports = { Encode, Decode };
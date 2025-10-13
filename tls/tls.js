const tcp = require('../tcp');

function Encode(srcIp, destIp, seqNum = 0, ackNum = 0, contentType, protocolVersion, payload) {
    // Step 1: Build TLS record
    const tlsLength = payload.length;
    const tlsHeader = Buffer.alloc(5);
    tlsHeader.writeUInt8(contentType, 0);
    tlsHeader.writeUInt16BE(protocolVersion, 1);
    tlsHeader.writeUInt16BE(tlsLength, 3);
    const tlsRecord = Buffer.concat([tlsHeader, payload]);

    // Step 2: Build TCP segment with TLS record as payload
    const tcpSegment = tcp.Encode(
        srcIp,
        destIp,
        51723,
        443,
        seqNum,
        ackNum,
        { psh: true, ack: true },
        65535,
        0,
        Buffer.alloc(0),
        tlsRecord
    );

    return tcpSegment;
}


function Decode(packet) {
    // Step 1: Decode TCP
    const tcpDecoded = tcp.Decode(packet);

    // Step 2: Extract TLS data from TCP payload
    const tlsData = tcpDecoded.dataPayload;

    // Step 3: Decode TLS header
    let tlsDecoded = {};
    tlsDecoded.contentType = tlsData.readUInt8(0);
    tlsDecoded.protocolVersion = tlsData.readUInt16BE(1);
    tlsDecoded.length = tlsData.readUInt16BE(3);
    tlsDecoded.payload = tlsData.slice(5, 5 + tlsDecoded.length);

    return {
        tcp: tcpDecoded,
        tls: tlsDecoded
    };
}


module.exports = { Encode, Decode }
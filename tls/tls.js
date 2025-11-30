const tcp = require('../tcp/tcp');
const { checkAndRead16, checkAndWrite16, checkAndRead8, checkAndWrite8 } = require('../util')

function Encode(srcIp, destIp, seqNum = 0, ackNum = 0, contentType, protocolVersion, payload) {
    // Step 1: Build TLS record
    const tlsLength = payload.length;
    const tlsHeader = Buffer.alloc(5);
    checkAndWrite8(tlsHeader, contentType, 0);
    checkAndWrite16(tlsHeader, protocolVersion, 1);
    checkAndWrite16(tlsHeader, tlsLength, 3);
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

    if (tcpDecoded) {
        console.log("Error deciding tcp, Potentially malformed packet");
    }
    // Step 2: Extract TLS data from TCP payload
    const tlsData = tcpDecoded.dataPayload;

    // Step 3: Decode TLS header
    let tlsDecoded = {};
    tlsDecoded.contentType = tlsData.readUInt8(0);
    tlsDecoded.protocolVersion = checkAndRead16(tlsData, 1);
    tlsDecoded.length = checkAndRead16(tlsData, 3);
    tlsDecoded.payload = tlsData.slice(5, 5 + tlsDecoded.length);

    return {
        tcp: tcpDecoded,
        tls: tlsDecoded
    };
}


module.exports = { Encode, Decode }
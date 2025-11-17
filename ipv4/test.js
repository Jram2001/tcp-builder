// ipv4-test.js
// Comprehensive test suite for IPv4 packet encoder

const { Encode, Decode } = require('./ipv4');

let testCount = 0;
let passedTests = 0;
let failedTests = [];

function assert(condition, testName) {
    testCount++;
    if (condition) {
        console.log(`✅ PASS: ${testName}`);
        passedTests++;
    } else {
        console.log(`❌ FAIL: ${testName}`);
        failedTests.push(testName);
    }
}

function assertEqual(actual, expected, testName) {
    const condition = actual === expected;
    assert(condition, testName);
    if (!condition) {
        console.log(`  Expected: ${expected}`);
        console.log(`  Actual: ${actual}`);
    }
}

function assertBufferEqual(actual, expected, testName) {
    const condition = Buffer.compare(actual, expected) === 0;
    assert(condition, testName);
    if (!condition) {
        console.log(`  Expected: ${expected.toString('hex')}`);
        console.log(`  Actual: ${actual.toString('hex')}`);
    }
}

function assertThrows(fn, testName) {
    testCount++;
    try {
        fn();
        console.log(`❌ FAIL: ${testName} (expected error but none thrown)`);
        failedTests.push(testName);
    } catch (error) {
        console.log(`✅ PASS: ${testName}`);
        passedTests++;
    }
}

console.log('🧪 Starting IPv4 Packet Encoder Test Suite\n');

// ===== Test 1: Basic IPv4 Packet =====
console.log('📝 Test 1: Basic IPv4 Packet (TCP)');
try {
    const payload = Buffer.from('Hello IPv4!');
    const packet = Encode(
        '192.168.1.1',
        '192.168.1.2',
        4,
        0,
        0,
        12345,
        '',
        0,
        64,
        'tcp',
        [],
        payload
    );

    assert(Buffer.isBuffer(packet), 'Packet is Buffer');
    assertEqual(packet.length, 20 + payload.length, 'Packet length correct');

    const decoded = Decode(packet);
    assertEqual(decoded.version, 4, 'Version correct');
    assertEqual(decoded.IHL, 5, 'IHL correct (no options)');
    assertEqual(decoded.headerLength, 20, 'Header length correct');
    assertEqual(decoded.protocol, 6, 'TCP protocol correct');
    assertEqual(decoded.ttl, 64, 'TTL correct');
    assertEqual(decoded.srcIp, '192.168.1.1', 'Source IP correct');
    assertEqual(decoded.destIp, '192.168.1.2', 'Destination IP correct');

} catch (error) {
    console.log(`❌ FAIL: Basic IPv4 Packet test - ${error.message}`);
    failedTests.push('Basic IPv4 Packet test');
}

// ===== Test 2: Round-trip Encode/Decode =====
console.log('\n📝 Test 2: Round-trip Encode/Decode');
try {
    const payload = Buffer.from('Round-trip test data');
    const packet = Encode(
        '10.0.0.1',
        '10.0.0.2',
        4,
        32,
        2,
        54321,
        'df',
        0,
        128,
        'udp',
        [],
        payload
    );

    const decoded = Decode(packet);
    assertEqual(decoded.version, 4, 'Version round-trip');
    assertEqual(decoded.DSCP, 32, 'DSCP round-trip');
    assertEqual(decoded.ECN, 2, 'ECN round-trip');
    assertEqual(decoded.identification, 54321, 'Identification round-trip');
    assertEqual(decoded.flags.DF, true, 'DF flag round-trip');
    assertEqual(decoded.flags.MF, false, 'MF flag round-trip');
    assertEqual(decoded.fragmentOffset, 0, 'Fragment offset round-trip');
    assertEqual(decoded.ttl, 128, 'TTL round-trip');
    assertEqual(decoded.protocol, 17, 'UDP protocol round-trip');
    assertEqual(decoded.srcIp, '10.0.0.1', 'Source IP round-trip');
    assertEqual(decoded.destIp, '10.0.0.2', 'Destination IP round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 3: Different Protocols =====
console.log('\n📝 Test 3: Different Protocols');
try {
    const payload = Buffer.from('Protocol test');

    const icmpPacket = Encode('1.1.1.1', '8.8.8.8', 4, 0, 0, 1, '', 0, 64, 'icmp', [], payload);
    const tcpPacket = Encode('1.1.1.1', '8.8.8.8', 4, 0, 0, 2, '', 0, 64, 'tcp', [], payload);
    const udpPacket = Encode('1.1.1.1', '8.8.8.8', 4, 0, 0, 3, '', 0, 64, 'udp', [], payload);
    const ospfPacket = Encode('1.1.1.1', '8.8.8.8', 4, 0, 0, 4, '', 0, 64, 'ospf', [], payload);

    assertEqual(Decode(icmpPacket).protocol, 1, 'ICMP protocol correct');
    assertEqual(Decode(tcpPacket).protocol, 6, 'TCP protocol correct');
    assertEqual(Decode(udpPacket).protocol, 17, 'UDP protocol correct');
    assertEqual(Decode(ospfPacket).protocol, 89, 'OSPF protocol correct');

} catch (error) {
    console.log(`❌ FAIL: Different protocols test - ${error.message}`);
    failedTests.push('Different protocols test');
}

// ===== Test 4: Flags Testing =====
console.log('\n📝 Test 4: Flags Testing');
try {
    const payload = Buffer.from('Flags test');

    const dfPacket = Encode('192.168.0.1', '192.168.0.2', 4, 0, 0, 100, 'df', 0, 64, 'tcp', [], payload);
    const mfPacket = Encode('192.168.0.1', '192.168.0.2', 4, 0, 0, 101, 'mf', 0, 64, 'tcp', [], payload);
    const bothPacket = Encode('192.168.0.1', '192.168.0.2', 4, 0, 0, 102, 'dfmf', 0, 64, 'tcp', [], payload);
    const noFlagsPacket = Encode('192.168.0.1', '192.168.0.2', 4, 0, 0, 103, '', 0, 64, 'tcp', [], payload);

    const dfDecoded = Decode(dfPacket);
    const mfDecoded = Decode(mfPacket);
    const bothDecoded = Decode(bothPacket);
    const noFlagsDecoded = Decode(noFlagsPacket);

    assertEqual(dfDecoded.flags.DF, true, 'DF flag set');
    assertEqual(dfDecoded.flags.MF, false, 'MF flag not set');

    assertEqual(mfDecoded.flags.DF, false, 'DF flag not set');
    assertEqual(mfDecoded.flags.MF, true, 'MF flag set');

    assertEqual(bothDecoded.flags.DF, true, 'Both flags: DF set');
    assertEqual(bothDecoded.flags.MF, true, 'Both flags: MF set');

    assertEqual(noFlagsDecoded.flags.DF, false, 'No flags: DF not set');
    assertEqual(noFlagsDecoded.flags.MF, false, 'No flags: MF not set');

} catch (error) {
    console.log(`❌ FAIL: Flags testing - ${error.message}`);
    failedTests.push('Flags testing');
}

// ===== Test 5: Fragment Offset =====
console.log('\n📝 Test 5: Fragment Offset');
try {
    const payload = Buffer.from('Fragment test');

    const packet1 = Encode('10.0.0.1', '10.0.0.2', 4, 0, 0, 200, 'mf', 0, 64, 'tcp', [], payload);
    const packet2 = Encode('10.0.0.1', '10.0.0.2', 4, 0, 0, 200, 'mf', 185, 64, 'tcp', [], payload);
    const packet3 = Encode('10.0.0.1', '10.0.0.2', 4, 0, 0, 200, '', 370, 64, 'tcp', [], payload);

    assertEqual(Decode(packet1).fragmentOffset, 0, 'First fragment offset');
    assertEqual(Decode(packet2).fragmentOffset, 185, 'Second fragment offset');
    assertEqual(Decode(packet3).fragmentOffset, 370, 'Third fragment offset');

} catch (error) {
    console.log(`❌ FAIL: Fragment offset test - ${error.message}`);
    failedTests.push('Fragment offset test');
}

// ===== Test 6: IPv4 Options =====
console.log('\n📝 Test 6: IPv4 Options');
try {
    const payload = Buffer.from('Options test');

    // Record Route option
    const rrPacket = Encode('172.16.0.1', '172.16.0.2', 4, 0, 0, 300, '', 0, 64, 'tcp',
        [{ type: 'RR', length: 11 }], payload);

    const rrDecoded = Decode(rrPacket);
    assertEqual(rrDecoded.IHL, 8, 'IHL with RR option (20 + 11 + 1 padding = 32 bytes / 4)');
    assertEqual(rrDecoded.hasOptions, true, 'Has options flag set');
    assertEqual(rrDecoded.optionsLength, 12, 'Options length correct (11 + 1 padding)');

    // NOP option
    const nopPacket = Encode('172.16.0.1', '172.16.0.2', 4, 0, 0, 301, '', 0, 64, 'tcp',
        [{ type: 'NOP' }, { type: 'NOP' }, { type: 'NOP' }, { type: 'NOP' }], payload);

    const nopDecoded = Decode(nopPacket);
    assertEqual(nopDecoded.IHL, 6, 'IHL with NOP options (20 + 4 = 24 bytes / 4)');

    // Multiple options
    const multiPacket = Encode('172.16.0.1', '172.16.0.2', 4, 0, 0, 302, '', 0, 64, 'tcp',
        [{ type: 'NOP' }, { type: 'RR', length: 7 }], payload);

    const multiDecoded = Decode(multiPacket);
    assertEqual(multiDecoded.hasOptions, true, 'Multiple options: has options');
    assertEqual(multiDecoded.optionsLength, 8, 'Multiple options length (1 + 7 = 8 bytes)');

} catch (error) {
    console.log(`❌ FAIL: IPv4 options test - ${error.message}`);
    failedTests.push('IPv4 options test');
}

// ===== Test 7: Empty Payload =====
console.log('\n📝 Test 7: Empty Payload');
try {
    const packet = Encode('127.0.0.1', '127.0.0.1', 4, 0, 0, 0, '', 0, 255, 'tcp', [], Buffer.alloc(0));
    const decoded = Decode(packet);

    assertEqual(packet.length, 20, 'Empty payload packet length');
    assertEqual(decoded.totalLength, 20, 'Empty payload total length');

} catch (error) {
    console.log(`❌ FAIL: Empty payload test - ${error.message}`);
    failedTests.push('Empty payload test');
}

// ===== Test 8: Maximum Size Payload =====
console.log('\n📝 Test 8: Maximum Size Payload');
try {
    const maxPayload = Buffer.alloc(65515, 0xAB); // 65535 - 20 bytes header
    const packet = Encode('10.1.1.1', '10.1.1.2', 4, 0, 0, 999, '', 0, 64, 'tcp', [], maxPayload);
    const decoded = Decode(packet);

    assertEqual(packet.length, 65535, 'Maximum packet size');
    assertEqual(decoded.totalLength, 65535, 'Maximum total length');

} catch (error) {
    console.log(`❌ FAIL: Maximum size payload test - ${error.message}`);
    failedTests.push('Maximum size payload test');
}

// ===== Test 9: DSCP and ECN Values =====
console.log('\n📝 Test 9: DSCP and ECN Values');
try {
    const payload = Buffer.from('DSCP/ECN test');

    // Different DSCP values
    const dscp0 = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 500, '', 0, 64, 'tcp', [], payload);
    const dscp32 = Encode('1.1.1.1', '2.2.2.2', 4, 32, 0, 501, '', 0, 64, 'tcp', [], payload);
    const dscp63 = Encode('1.1.1.1', '2.2.2.2', 4, 63, 0, 502, '', 0, 64, 'tcp', [], payload);

    assertEqual(Decode(dscp0).DSCP, 0, 'DSCP value 0');
    assertEqual(Decode(dscp32).DSCP, 32, 'DSCP value 32');
    assertEqual(Decode(dscp63).DSCP, 63, 'DSCP value 63');

    // Different ECN values
    const ecn0 = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 503, '', 0, 64, 'tcp', [], payload);
    const ecn1 = Encode('1.1.1.1', '2.2.2.2', 4, 0, 1, 504, '', 0, 64, 'tcp', [], payload);
    const ecn2 = Encode('1.1.1.1', '2.2.2.2', 4, 0, 2, 505, '', 0, 64, 'tcp', [], payload);
    const ecn3 = Encode('1.1.1.1', '2.2.2.2', 4, 0, 3, 506, '', 0, 64, 'tcp', [], payload);

    assertEqual(Decode(ecn0).ECN, 0, 'ECN value 0');
    assertEqual(Decode(ecn1).ECN, 1, 'ECN value 1');
    assertEqual(Decode(ecn2).ECN, 2, 'ECN value 2');
    assertEqual(Decode(ecn3).ECN, 3, 'ECN value 3');

} catch (error) {
    console.log(`❌ FAIL: DSCP and ECN test - ${error.message}`);
    failedTests.push('DSCP and ECN test');
}

// ===== Test 10: Case Insensitivity =====
console.log('\n📝 Test 10: Case Insensitivity');
try {
    const payload = Buffer.from('Case test');

    const upperProtocol = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 600, '', 0, 64, 'TCP', [], payload);
    const lowerProtocol = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 601, '', 0, 64, 'tcp', [], payload);
    const mixedProtocol = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 602, '', 0, 64, 'TcP', [], payload);

    assertEqual(Decode(upperProtocol).protocol, 6, 'Uppercase protocol');
    assertEqual(Decode(lowerProtocol).protocol, 6, 'Lowercase protocol');
    assertEqual(Decode(mixedProtocol).protocol, 6, 'Mixed case protocol');

    const upperFlags = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 603, 'DF', 0, 64, 'tcp', [], payload);
    const lowerFlags = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 604, 'df', 0, 64, 'tcp', [], payload);
    const mixedFlags = Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 605, 'Df', 0, 64, 'tcp', [], payload);

    assertEqual(Decode(upperFlags).flags.DF, true, 'Uppercase flags');
    assertEqual(Decode(lowerFlags).flags.DF, true, 'Lowercase flags');
    assertEqual(Decode(mixedFlags).flags.DF, true, 'Mixed case flags');

} catch (error) {
    console.log(`❌ FAIL: Case insensitivity test - ${error.message}`);
    failedTests.push('Case insensitivity test');
}

// ===== Test 11: Error Handling - Invalid Version =====
console.log('\n📝 Test 11: Error Handling - Invalid Version');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 6, 0, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'Invalid version throws error');

// ===== Test 12: Error Handling - Invalid DSCP =====
console.log('\n📝 Test 12: Error Handling - Invalid DSCP');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 64, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'DSCP > 63 throws error');

assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, -1, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'DSCP < 0 throws error');

// ===== Test 13: Error Handling - Invalid ECN =====
console.log('\n📝 Test 13: Error Handling - Invalid ECN');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 4, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'ECN > 3 throws error');

// ===== Test 14: Error Handling - Invalid TTL =====
console.log('\n📝 Test 14: Error Handling - Invalid TTL');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 256, 'tcp', [], Buffer.from('test'));
}, 'TTL > 255 throws error');

// ===== Test 15: Error Handling - Invalid Protocol =====
console.log('\n📝 Test 15: Error Handling - Invalid Protocol');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'invalid', [], Buffer.from('test'));
}, 'Invalid protocol throws error');

// ===== Test 16: Error Handling - Invalid IP Address =====
console.log('\n📝 Test 16: Error Handling - Invalid IP Address');
assertThrows(() => {
    Encode('256.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'Invalid IP octet (> 255) throws error');

assertThrows(() => {
    Encode('192.168.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'Invalid IP format (too few octets) throws error');

assertThrows(() => {
    Encode('192.168.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'tcp', [], Buffer.from('test'));
}, 'Invalid IP format (too many octets) throws error');

// ===== Test 17: Error Handling - Fragment Offset Range =====
console.log('\n📝 Test 17: Error Handling - Fragment Offset Range');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 8192, 64, 'tcp', [], Buffer.from('test'));
}, 'Fragment offset > 8191 throws error');

// ===== Test 18: Error Handling - Packet Too Large =====
console.log('\n📝 Test 18: Error Handling - Packet Too Large');
assertThrows(() => {
    const hugePayload = Buffer.alloc(65516); // 65535 - 20 + 1 = too large
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'tcp', [], hugePayload);
}, 'Packet exceeding 65535 bytes throws error');

// ===== Test 19: Error Handling - Invalid Payload Type =====
console.log('\n📝 Test 19: Error Handling - Invalid Payload Type');
assertThrows(() => {
    Encode('1.1.1.1', '2.2.2.2', 4, 0, 0, 1, '', 0, 64, 'tcp', [], 'not a buffer');
}, 'Non-Buffer payload throws error');

// ===== Test 20: Checksum Verification =====
console.log('\n📝 Test 20: Checksum Verification');
try {
    const payload = Buffer.from('Checksum test');
    const packet = Encode('192.168.1.1', '192.168.1.2', 4, 0, 0, 1000, '', 0, 64, 'tcp', [], payload);

    // Extract header checksum
    const storedChecksum = packet.readUInt16BE(10);

    // Zero out checksum field and recalculate
    const headerCopy = Buffer.from(packet.slice(0, 20));
    headerCopy.writeUInt16BE(0, 10);

    let sum = 0;
    for (let i = 0; i < headerCopy.length; i += 2) {
        const word = (headerCopy[i] << 8) | headerCopy[i + 1];
        sum += word;
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
    }
    const calculatedChecksum = ~sum & 0xFFFF;

    assertEqual(storedChecksum, calculatedChecksum, 'Checksum is valid');

} catch (error) {
    console.log(`❌ FAIL: Checksum verification - ${error.message}`);
    failedTests.push('Checksum verification');
}

// ===== Test Results Summary =====
console.log('\n📊 Test Results Summary');
console.log('='.repeat(50));
console.log(`Total Tests: ${testCount}`);
console.log(`✅ Passed: ${passedTests}`);
console.log(`❌ Failed: ${testCount - passedTests}`);
console.log(`Success Rate: ${((passedTests / testCount) * 100).toFixed(1)}%`);

if (failedTests.length > 0) {
    console.log('\n❌ Failed Tests:');
    failedTests.forEach((test, index) => {
        console.log(`   ${index + 1}. ${test}`);
    });
    process.exit(1);
} else {
    console.log('\n🎉 All tests passed!');
    process.exit(0);
}
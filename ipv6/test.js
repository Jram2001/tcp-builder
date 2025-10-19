const { Encode, Decode } = require('./ipv6'); // Adjust path as needed

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

console.log('🧪 Starting IPv6 Packet Builder Test Suite\n');

// ===== Test 1: Basic IPv6 Packet Encoding =====
console.log('📝 Test 1: Basic IPv6 Packet Encoding');
try {
    const payload = Buffer.from('Hello IPv6!');
    const packet = Encode(
        '2001:db8::1',      // source IP
        '2001:db8::2',      // destination IP
        0,                  // DSCP
        0,                  // ECN
        payload,            // payload
        12345,              // flow label
        6,                  // next header (TCP)
        64                  // hop limit
    );

    assert(Buffer.isBuffer(packet), 'Packet is Buffer');
    assertEqual(packet.length, 40 + payload.length, 'Packet length correct (40 byte header + payload)');

    // Check first byte contains version 6
    const firstByte = packet.readUInt8(0);
    const version = firstByte >> 4;
    assertEqual(version, 6, 'IPv6 version correct');

} catch (error) {
    console.log(`❌ FAIL: Basic IPv6 encoding test - ${error.message}`);
    failedTests.push('Basic IPv6 encoding test');
}

// ===== Test 2: Round-trip Encode/Decode =====
console.log('\n📝 Test 2: Round-trip Encode/Decode');
try {
    const payload = Buffer.from('Round-trip test data');
    const packet = Encode(
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'fe80::1',
        10,     // DSCP
        2,      // ECN
        payload,
        54321,  // flow label
        17,     // next header (UDP)
        128     // hop limit
    );

    const decoded = Decode(packet);

    assertEqual(decoded.Version, 'ipv6', 'Version round-trip');
    assertEqual(decoded.DSCP, 10, 'DSCP round-trip');
    assertEqual(decoded.ECN, 2, 'ECN round-trip');
    assertEqual(decoded.flowLabel, 54321, 'Flow label round-trip');
    assertEqual(decoded.payloadLength, payload.length, 'Payload length round-trip');
    assertEqual(decoded.nextHeader, 17, 'Next header round-trip');
    assertEqual(decoded.hopLimit, 128, 'Hop limit round-trip');
    assertBufferEqual(decoded.payload, payload, 'Payload content round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 3: IPv6 Address Formats =====
console.log('\n📝 Test 3: IPv6 Address Formats');
try {
    const payload = Buffer.from('Address test');

    // Test compressed notation with ::
    const packet1 = Encode('2001:db8::1', '2001:db8::2', 0, 0, payload, 0, 6, 64);
    const decoded1 = Decode(packet1);
    assertEqual(decoded1.sourceAddr, '2001:db8:0:0:0:0:0:1', 'Compressed source address decoded');
    assertEqual(decoded1.destinationAddr, '2001:db8:0:0:0:0:0:2', 'Compressed dest address decoded');

    // Test full IPv6 address
    const packet2 = Encode(
        '2001:0db8:0000:0000:0000:ff00:0042:8329',
        'fe80:0000:0000:0000:0204:61ff:fe9d:f156',
        0, 0, payload, 0, 6, 64
    );
    const decoded2 = Decode(packet2);
    assert(decoded2.sourceAddr.includes('2001'), 'Full source address decoded');
    assert(decoded2.destinationAddr.includes('fe80'), 'Full dest address decoded');

    // Test loopback
    const packet3 = Encode('::1', '::1', 0, 0, payload, 0, 6, 64);
    const decoded3 = Decode(packet3);
    assertEqual(decoded3.sourceAddr, '0:0:0:0:0:0:0:1', 'Loopback address decoded');

} catch (error) {
    console.log(`❌ FAIL: IPv6 address formats test - ${error.message}`);
    failedTests.push('IPv6 address formats test');
}

// ===== Test 4: Traffic Class (DSCP + ECN) =====
console.log('\n📝 Test 4: Traffic Class (DSCP + ECN)');
try {
    const payload = Buffer.from('Traffic class test');

    // Test various DSCP values (6 bits, 0-63)
    const testCases = [
        { dscp: 0, ecn: 0 },
        { dscp: 10, ecn: 1 },
        { dscp: 46, ecn: 2 },  // EF (Expedited Forwarding)
        { dscp: 63, ecn: 3 },  // Max values
    ];

    testCases.forEach(({ dscp, ecn }) => {
        const packet = Encode('2001:db8::1', '2001:db8::2', dscp, ecn, payload, 0, 6, 64);
        const decoded = Decode(packet);
        assertEqual(decoded.DSCP, dscp, `DSCP ${dscp} correct`);
        assertEqual(decoded.ECN, ecn, `ECN ${ecn} correct`);
    });

} catch (error) {
    console.log(`❌ FAIL: Traffic class test - ${error.message}`);
    failedTests.push('Traffic class test');
}

// ===== Test 5: Flow Label =====
console.log('\n📝 Test 5: Flow Label');
try {
    const payload = Buffer.from('Flow label test');

    // Test various flow labels (20 bits, 0 to 1048575)
    const flowLabels = [0, 1, 12345, 99999, 524287, 1048575]; // Max is 0xFFFFF

    flowLabels.forEach(flowLabel => {
        const packet = Encode('2001:db8::1', '2001:db8::2', 0, 0, payload, flowLabel, 6, 64);
        const decoded = Decode(packet);
        assertEqual(decoded.flowLabel, flowLabel, `Flow label ${flowLabel} correct`);
    });

} catch (error) {
    console.log(`❌ FAIL: Flow label test - ${error.message}`);
    failedTests.push('Flow label test');
}

// ===== Test 6: Next Header Values =====
console.log('\n📝 Test 6: Next Header Protocol Values');
try {
    const payload = Buffer.from('Next header test');

    const protocols = [
        { value: 6, name: 'TCP' },
        { value: 17, name: 'UDP' },
        { value: 58, name: 'ICMPv6' },
        { value: 0, name: 'Hop-by-Hop' },
        { value: 43, name: 'Routing' },
        { value: 44, name: 'Fragment' },
    ];

    protocols.forEach(({ value, name }) => {
        const packet = Encode('2001:db8::1', '2001:db8::2', 0, 0, payload, 0, value, 64);
        const decoded = Decode(packet);
        assertEqual(decoded.nextHeader, value, `Next header ${name} (${value}) correct`);
    });

} catch (error) {
    console.log(`❌ FAIL: Next header test - ${error.message}`);
    failedTests.push('Next header test');
}

// ===== Test 7: Hop Limit Values =====
console.log('\n📝 Test 7: Hop Limit');
try {
    const payload = Buffer.from('Hop limit test');

    const hopLimits = [1, 32, 64, 128, 255];

    hopLimits.forEach(hopLimit => {
        const packet = Encode('2001:db8::1', '2001:db8::2', 0, 0, payload, 0, 6, hopLimit);
        const decoded = Decode(packet);
        assertEqual(decoded.hopLimit, hopLimit, `Hop limit ${hopLimit} correct`);
    });

} catch (error) {
    console.log(`❌ FAIL: Hop limit test - ${error.message}`);
    failedTests.push('Hop limit test');
}

// ===== Test 8: Empty Payload =====
console.log('\n📝 Test 8: Empty Payload');
try {
    const packet = Encode('::1', '::1', 0, 0, Buffer.alloc(0), 0, 59, 64); // Next Header 59 = No Next Header
    const decoded = Decode(packet);

    assertEqual(decoded.payloadLength, 0, 'Empty payload length correct');
    assertEqual(decoded.payload.length, 0, 'Empty payload buffer length correct');
    assertBufferEqual(decoded.payload, Buffer.alloc(0), 'Empty payload decoded correctly');

} catch (error) {
    console.log(`❌ FAIL: Empty payload test - ${error.message}`);
    failedTests.push('Empty payload test');
}

// ===== Test 9: Large Payload =====
console.log('\n📝 Test 9: Large Payload');
try {
    // Maximum payload for standard IPv6 (65535 bytes max for length field)
    const largePayload = Buffer.alloc(16384, 0xAB); // 16 KB
    const packet = Encode('2001:db8::cafe', '2001:db8::babe', 0, 0, largePayload, 0, 6, 64);
    const decoded = Decode(packet);

    assertEqual(decoded.payloadLength, largePayload.length, 'Large payload length correct');
    assertBufferEqual(decoded.payload, largePayload, 'Large payload content correct');

} catch (error) {
    console.log(`❌ FAIL: Large payload test - ${error.message}`);
    failedTests.push('Large payload test');
}

// ===== Test 10: Header Size Verification =====
console.log('\n📝 Test 10: Header Size Verification');
try {
    const payload = Buffer.from('Header size test');
    const packet = Encode('2001:db8::1', '2001:db8::2', 0, 0, payload, 0, 6, 64);

    // IPv6 header is always exactly 40 bytes
    assertEqual(packet.length - payload.length, 40, 'IPv6 header is exactly 40 bytes');

    // Verify payload starts at byte 40
    const extractedPayload = packet.slice(40);
    assertBufferEqual(extractedPayload, payload, 'Payload starts at correct offset');

} catch (error) {
    console.log(`❌ FAIL: Header size test - ${error.message}`);
    failedTests.push('Header size test');
}

// ===== Test 11: Binary Header Structure =====
console.log('\n📝 Test 11: Binary Header Structure');
try {
    const payload = Buffer.from('Structure test');
    const packet = Encode('2001:db8::1', '2001:db8::2', 12, 3, payload, 0xABCDE, 6, 64);

    // Manually verify first word structure
    const firstWord = packet.readUInt32BE(0);
    const version = (firstWord >> 28) & 0xF;
    const trafficClass = (firstWord >> 20) & 0xFF;
    const flowLabel = firstWord & 0xFFFFF;

    assertEqual(version, 6, 'Version in first word correct');
    assertEqual(trafficClass, (12 << 2) | 3, 'Traffic class in first word correct');
    assertEqual(flowLabel, 0xABCDE, 'Flow label in first word correct');

    // Verify bytes 4-7
    const payloadLength = packet.readUInt16BE(4);
    const nextHeader = packet.readUInt8(6);
    const hopLimit = packet.readUInt8(7);

    assertEqual(payloadLength, payload.length, 'Payload length field correct');
    assertEqual(nextHeader, 6, 'Next header field correct');
    assertEqual(hopLimit, 64, 'Hop limit field correct');

} catch (error) {
    console.log(`❌ FAIL: Binary header structure test - ${error.message}`);
    failedTests.push('Binary header structure test');
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
    console.log('\n🎉 All tests passed! Your IPv6 implementation is solid! 🚀');
    process.exit(0);
}

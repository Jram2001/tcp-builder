const UDP = require('./udp');

// Test utilities
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

console.log('🧪 Starting UDP Packet Builder Test Suite\n');

// ===== Test 1: Basic UDP Packet =====
console.log('📝 Test 1: Basic UDP Packet');
try {
    const data = Buffer.from('Hello UDP!');
    const udpPacket = UDP.Encode('192.168.1.10', '192.168.1.20', 40000, 53, data);
    const decoded = UDP.Decode(udpPacket);

    assert(Buffer.isBuffer(udpPacket), 'UDP packet is Buffer');
    assertEqual(decoded.SourcePort, 40000, 'Source port correct');
    assertEqual(decoded.destinationPort, 53, 'Destination port correct');
    assertEqual(decoded.length, 8 + data.length, 'Length correct');
    assertBufferEqual(decoded.data, data, 'Payload matches');

} catch (error) {
    console.log(`❌ FAIL: Basic UDP packet test - ${error.message}`);
    failedTests.push('Basic UDP packet test');
}

// ===== Test 2: Checksum Validation =====
console.log('\n📝 Test 2: Checksum Validation');
try {
    const payload1 = Buffer.from('Test 1');
    const payload2 = Buffer.from('Test 2');

    const packet1 = UDP.Encode('10.0.0.1', '10.0.0.2', 1234, 5678, payload1);
    const packet2 = UDP.Encode('10.0.0.1', '10.0.0.2', 1234, 5678, payload2);

    const decoded1 = UDP.Decode(packet1);
    const decoded2 = UDP.Decode(packet2);

    assert(decoded1.checksum !== decoded2.checksum, 'Different payloads produce different checksums');
    assert(decoded1.checksum > 0, 'Checksum non-zero');

} catch (error) {
    console.log(`❌ FAIL: Checksum validation test - ${error.message}`);
    failedTests.push('Checksum validation test');
}

// ===== Test 3: Round-trip Encoding/Decoding =====
console.log('\n📝 Test 3: Round-trip Encode/Decode');
try {
    const payload = Buffer.from('Round-trip test');
    const packet = UDP.Encode('172.16.0.1', '172.16.0.100', 5000, 6000, payload);
    const decoded = UDP.Decode(packet);

    assertEqual(decoded.SourcePort, 5000, 'Source port round-trip');
    assertEqual(decoded.destinationPort, 6000, 'Destination port round-trip');
    assertEqual(decoded.length, 8 + payload.length, 'Length round-trip');
    assertBufferEqual(decoded.data, payload, 'Payload round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 4: Empty Payload =====
console.log('\n📝 Test 4: Empty Payload');
try {
    const packet = UDP.Encode('127.0.0.1', '127.0.0.1', 1, 2, Buffer.alloc(0));
    const decoded = UDP.Decode(packet);

    assertEqual(decoded.length, 8, 'Length for empty payload');
    assertBufferEqual(decoded.data, Buffer.alloc(0), 'Empty payload decoded correctly');

} catch (error) {
    console.log(`❌ FAIL: Empty payload test - ${error.message}`);
    failedTests.push('Empty payload test');
}

// ===== Test 5: Edge Cases =====
console.log('\n📝 Test 5: Edge Cases');
try {
    // Maximum port numbers
    const packetMax = UDP.Encode('255.255.255.255', '0.0.0.0', 65535, 65535);
    const decodedMax = UDP.Decode(packetMax);
    assertEqual(decodedMax.SourcePort, 65535, 'Max source port');
    assertEqual(decodedMax.destinationPort, 65535, 'Max destination port');

    // Minimum port numbers
    const packetMin = UDP.Encode('0.0.0.0', '255.255.255.255', 0, 0);
    const decodedMin = UDP.Decode(packetMin);
    assertEqual(decodedMin.SourcePort, 0, 'Min source port');
    assertEqual(decodedMin.destinationPort, 0, 'Min destination port');

} catch (error) {
    console.log(`❌ FAIL: Edge cases test - ${error.message}`);
    failedTests.push('Edge cases test');
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

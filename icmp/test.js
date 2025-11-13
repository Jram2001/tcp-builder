const ICMP = require('./icmp'); // Assuming you have Encode and Decode functions

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

console.log('🧪 Starting ICMP Packet Builder Test Suite\n');

// ===== Test 1: Basic Echo Request =====
console.log('📝 Test 1: Basic Echo Request');
try {
    const data = Buffer.from('Hello ICMP!');
    const icmpPacket = ICMP.Encode(8, 0, 0x1234, 0x0001, data); // Type 8 = Echo Request
    const decoded = ICMP.Decode(icmpPacket);

    assert(Buffer.isBuffer(icmpPacket), 'ICMP packet is Buffer');
    assertEqual(decoded.type, 8, 'Type correct');
    assertEqual(decoded.code, 0, 'Code correct');
    assertEqual(decoded.identifier, 0x1234, 'Identifier correct');
    assertEqual(decoded.sequence, 0x0001, 'Sequence correct');
    assertBufferEqual(decoded.data, data, 'Payload matches');

} catch (error) {
    console.log(`❌ FAIL: Basic Echo Request test - ${error.message}`);
    failedTests.push('Basic Echo Request test');
}

// ===== Test 2: Checksum Validation =====
console.log('\n📝 Test 2: Checksum Validation');
try {
    const payload1 = Buffer.from('Ping 1');
    const payload2 = Buffer.from('Ping 2');

    const packet1 = ICMP.Encode(8, 0, 0x1111, 0x0001, payload1);
    const packet2 = ICMP.Encode(8, 0, 0x1111, 0x0001, payload2);

    const decoded1 = ICMP.Decode(packet1);
    const decoded2 = ICMP.Decode(packet2);

    assert(decoded1.checksum !== decoded2.checksum, 'Different payloads produce different checksums');
    assert(decoded1.checksum > 0, 'Checksum non-zero');

} catch (error) {
    console.log(`❌ FAIL: Checksum validation test - ${error.message}`);
    failedTests.push('Checksum validation test');
}

// ===== Test 3: Round-trip Encode/Decode =====
console.log('\n📝 Test 3: Round-trip Encode/Decode');
try {
    const payload = Buffer.from('Round-trip ICMP');
    const packet = ICMP.Encode(8, 0, 0x4321, 0x0002, payload);
    const decoded = ICMP.Decode(packet);

    assertEqual(decoded.type, 8, 'Type round-trip');
    assertEqual(decoded.code, 0, 'Code round-trip');
    assertEqual(decoded.identifier, 0x4321, 'Identifier round-trip');
    assertEqual(decoded.sequence, 0x0002, 'Sequence round-trip');
    assertBufferEqual(decoded.data, payload, 'Payload round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 4: Empty Payload =====
console.log('\n📝 Test 4: Empty Payload');
try {
    const packet = ICMP.Encode(8, 0, 0x0000, 0x0000, Buffer.alloc(0));
    const decoded = ICMP.Decode(packet);

    assertEqual(decoded.data.length, 0, 'Empty payload length correct');
    assertBufferEqual(decoded.data, Buffer.alloc(0), 'Empty payload decoded correctly');

} catch (error) {
    console.log(`❌ FAIL: Empty payload test - ${error.message}`);
    failedTests.push('Empty payload test');
}

// ===== Test 5: Edge Cases =====
console.log('\n📝 Test 5: Edge Cases');
try {
    // Max identifier and sequence
    const packetMax = ICMP.Encode(8, 0xFF, 0xFFFF, 0xFFFF);
    const decodedMax = ICMP.Decode(packetMax);
    assertEqual(decodedMax.identifier, 0xFFFF, 'Max identifier');
    assertEqual(decodedMax.sequence, 0xFFFF, 'Max sequence');

    // Min identifier and sequence
    const packetMin = ICMP.Encode(8, 0, 0x0000, 0x0000);
    const decodedMin = ICMP.Decode(packetMin);
    assertEqual(decodedMin.identifier, 0x0000, 'Min identifier');
    assertEqual(decodedMin.sequence, 0x0000, 'Min sequence');

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

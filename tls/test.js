const TLS = require('./tls'); // Assuming Encode and Decode functions are exported

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

console.log('🧪 Starting TLS Packet Builder Test Suite\n');

// ===== Test 1: Basic Handshake Record =====
console.log('📝 Test 1: Basic TLS Handshake Record');
try {
    const payload = Buffer.from('Hello TLS!');
    const tcpSegment = TLS.Encode('192.168.1.2', '192.168.1.10', 1, 0, 0x16, 0x0303, payload);
    const decoded = TLS.Decode(tcpSegment);

    assert(Buffer.isBuffer(tcpSegment), 'TCP segment is Buffer');
    assertEqual(decoded.tls.contentType, 0x16, 'TLS ContentType correct');
    assertEqual(decoded.tls.protocolVersion, 0x0303, 'TLS ProtocolVersion correct');
    assertEqual(decoded.tls.length, payload.length, 'TLS length correct');
    assertBufferEqual(decoded.tls.payload, payload, 'TLS payload matches');

} catch (error) {
    console.log(`❌ FAIL: Basic TLS Handshake test - ${error.message}`);
    failedTests.push('Basic TLS Handshake test');
}

// ===== Test 2: Round-trip Encode/Decode =====
console.log('\n📝 Test 2: Round-trip Encode/Decode');
try {
    const payload = Buffer.from('Round-trip TLS');
    const tcpSegment = TLS.Encode('10.0.0.1', '10.0.0.2', 42, 17, 0x17, 0x0303, payload);
    const decoded = TLS.Decode(tcpSegment);

    assertEqual(decoded.tls.contentType, 0x17, 'TLS ContentType round-trip');
    assertEqual(decoded.tls.protocolVersion, 0x0303, 'TLS ProtocolVersion round-trip');
    assertEqual(decoded.tls.length, payload.length, 'TLS length round-trip');
    assertBufferEqual(decoded.tls.payload, payload, 'TLS payload round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 3: Empty Payload =====
console.log('\n📝 Test 3: Empty TLS Payload');
try {
    const tcpSegment = TLS.Encode('127.0.0.1', '127.0.0.1', 0, 0, 0x17, 0x0303, Buffer.alloc(0));
    const decoded = TLS.Decode(tcpSegment);

    assertEqual(decoded.tls.length, 0, 'Empty payload length correct');
    assertBufferEqual(decoded.tls.payload, Buffer.alloc(0), 'Empty payload decoded correctly');

} catch (error) {
    console.log(`❌ FAIL: Empty payload test - ${error.message}`);
    failedTests.push('Empty payload test');
}

// ===== Test 4: Multiple TLS Record Types =====
console.log('\n📝 Test 4: Multiple TLS Record Types');
try {
    const handshakePayload = Buffer.from('ClientHello');
    const appDataPayload = Buffer.from('EncryptedAppData');

    const handshakeSegment = TLS.Encode('192.168.0.1', '192.168.0.2', 1, 0, 0x16, 0x0303, handshakePayload);
    const appDataSegment = TLS.Encode('192.168.0.1', '192.168.0.2', 2, 1, 0x17, 0x0303, appDataPayload);

    const decodedHandshake = TLS.Decode(handshakeSegment);
    const decodedAppData = TLS.Decode(appDataSegment);

    assertEqual(decodedHandshake.tls.contentType, 0x16, 'Handshake ContentType correct');
    assertEqual(decodedAppData.tls.contentType, 0x17, 'Application Data ContentType correct');

} catch (error) {
    console.log(`❌ FAIL: Multiple TLS record types test - ${error.message}`);
    failedTests.push('Multiple TLS record types test');
}

// ===== Test 5: Edge Cases =====
console.log('\n📝 Test 5: Edge Cases');
try {
    // Maximum payload
    const maxPayload = Buffer.alloc(16384, 0xAA); // 16 KB, typical TLS max
    const tcpSegment = TLS.Encode('10.1.1.1', '10.1.1.2', 123, 456, 0x17, 0x0303, maxPayload);
    const decoded = TLS.Decode(tcpSegment);
    assertEqual(decoded.tls.length, maxPayload.length, 'Max payload length correct');
    assertBufferEqual(decoded.tls.payload, maxPayload, 'Max payload content correct');

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

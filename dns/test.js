const DNS = require('./dns'); // Your DNS module

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

console.log('🧪 Starting DNS Packet Builder Test Suite\n');

// ===== Test 1: Basic Header Encode/Decode =====
console.log('📝 Test 1: Basic Header Encode/Decode');
try {
    const flags = { qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, z: 0, rcode: 0 };
    const header = DNS.Encode(0x1234, flags, 1, 0, 0, 0);
    const decoded = DNS.Decode(header);

    assertEqual(header.length, 12, 'Header length is 12 bytes');
    assertEqual(decoded.transactionId, 0x1234, 'Transaction ID correct');
    assertEqual(decoded.flags.qr, 0, 'QR flag correct');
    assertEqual(decoded.flags.rd, 1, 'RD flag correct');
    assertEqual(decoded.questionCount, 1, 'Question count correct');
    assertEqual(decoded.answerCount, 0, 'Answer count correct');

} catch (error) {
    console.log(`❌ FAIL: Basic Header test - ${error.message}`);
    failedTests.push('Basic Header test');
}

// ===== Test 2: Flag Combinations =====
console.log('\n📝 Test 2: Flag Combinations');
try {
    // Test response flags
    const responseFlags = { qr: 1, opcode: 0, aa: 1, tc: 0, rd: 1, ra: 1, z: 0, rcode: 0 };
    const responseHeader = DNS.Encode(0x5678, responseFlags, 1, 2, 1, 1);
    const responseDecoded = DNS.Decode(responseHeader);

    assertEqual(responseDecoded.flags.qr, 1, 'Response flag correct');
    assertEqual(responseDecoded.flags.aa, 1, 'Authoritative flag correct');
    assertEqual(responseDecoded.flags.ra, 1, 'Recursion available flag correct');
    assertEqual(responseDecoded.answerCount, 2, 'Answer count correct');
    assertEqual(responseDecoded.authorityCount, 1, 'Authority count correct');

} catch (error) {
    console.log(`❌ FAIL: Flag combinations test - ${error.message}`);
    failedTests.push('Flag combinations test');
}

// ===== Test 3: Round-trip Encode/Decode =====
console.log('\n📝 Test 3: Round-trip Encode/Decode');
try {
    const originalFlags = { qr: 0, opcode: 2, aa: 0, tc: 1, rd: 0, ra: 0, z: 0, rcode: 3 };
    const header = DNS.Encode(0xABCD, originalFlags, 5, 10, 2, 3);
    const decoded = DNS.Decode(header);

    assertEqual(decoded.transactionId, 0xABCD, 'Transaction ID round-trip');
    assertEqual(decoded.flags.opcode, 2, 'Opcode round-trip');
    assertEqual(decoded.flags.tc, 1, 'Truncated flag round-trip');
    assertEqual(decoded.flags.rcode, 3, 'RCODE round-trip');
    assertEqual(decoded.questionCount, 5, 'Question count round-trip');
    assertEqual(decoded.answerCount, 10, 'Answer count round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 4: Question Building =====
console.log('\n📝 Test 4: Question Building');
try {
    const question = DNS.buildQuestion('google.com', DNS.DNS_TYPES.A, DNS.DNS_CLASSES.IN);

    assert(Buffer.isBuffer(question), 'Question is Buffer');
    assert(question.length > 10, 'Question has reasonable length');

    // Check type and class at the end (last 4 bytes)
    const typeClass = question.slice(-4);
    const expectedTypeClass = Buffer.from([0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
    assertBufferEqual(typeClass, expectedTypeClass, 'Type A and Class IN encoding correct');

} catch (error) {
    console.log(`❌ FAIL: Question building test - ${error.message}`);
    failedTests.push('Question building test');
}

// ===== Test 5: Complete DNS Query =====
console.log('\n📝 Test 5: Complete DNS Query');
try {
    const questions = [
        { domain: 'example.com', type: DNS.DNS_TYPES.A, class: DNS.DNS_CLASSES.IN },
        { domain: 'test.org', type: DNS.DNS_TYPES.MX, class: DNS.DNS_CLASSES.IN }
    ];
    const options = { transactionId: 0x9999 };

    const packet = DNS.CreateDNSQuery(questions, options);
    const decoded = DNS.Decode(packet.slice(0, 12)); // Decode header only

    assert(Buffer.isBuffer(packet), 'Query packet is Buffer');
    assert(packet.length > 12, 'Packet larger than header');
    assertEqual(decoded.transactionId, 0x9999, 'Custom transaction ID correct');
    assertEqual(decoded.questionCount, 2, 'Multiple questions count correct');
    assertEqual(decoded.flags.rd, 1, 'Recursion desired default set');

} catch (error) {
    console.log(`❌ FAIL: Complete DNS Query test - ${error.message}`);
    failedTests.push('Complete DNS Query test');
}

// ===== Test 6: DNS Constants =====
console.log('\n📝 Test 6: DNS Constants');
try {
    assertEqual(DNS.DNS_TYPES.A, 1, 'A record type constant');
    assertEqual(DNS.DNS_TYPES.MX, 15, 'MX record type constant');
    assertEqual(DNS.DNS_TYPES.AAAA, 28, 'AAAA record type constant');
    assertEqual(DNS.DNS_CLASSES.IN, 1, 'Internet class constant');

} catch (error) {
    console.log(`❌ FAIL: DNS Constants test - ${error.message}`);
    failedTests.push('DNS Constants test');
}

// ===== Test 7: Random Transaction ID =====
console.log('\n📝 Test 7: Random Transaction ID');
try {
    const packet1 = DNS.CreateDNSQuery([{ domain: 'test1.com', type: DNS.DNS_TYPES.A, class: DNS.DNS_CLASSES.IN }], {});
    const packet2 = DNS.CreateDNSQuery([{ domain: 'test2.com', type: DNS.DNS_TYPES.A, class: DNS.DNS_CLASSES.IN }], {});

    const decoded1 = DNS.Decode(packet1.slice(0, 12));
    const decoded2 = DNS.Decode(packet2.slice(0, 12));

    assert(decoded1.transactionId !== decoded2.transactionId, 'Random transaction IDs are different');
    assert(decoded1.transactionId >= 0 && decoded1.transactionId <= 0xFFFF, 'Transaction ID in valid range');
    assert(decoded2.transactionId >= 0 && decoded2.transactionId <= 0xFFFF, 'Transaction ID 2 in valid range');

} catch (error) {
    console.log(`❌ FAIL: Random Transaction ID test - ${error.message}`);
    failedTests.push('Random Transaction ID test');
}

// ===== Test 8: Edge Cases =====
console.log('\n📝 Test 8: Edge Cases');
try {
    // Maximum values test
    const maxFlags = { qr: 1, opcode: 15, aa: 1, tc: 1, rd: 1, ra: 1, z: 7, rcode: 15 };
    const maxHeader = DNS.Encode(0xFFFF, maxFlags, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    const maxDecoded = DNS.Decode(maxHeader);

    assertEqual(maxDecoded.transactionId, 0xFFFF, 'Max transaction ID');
    assertEqual(maxDecoded.flags.opcode, 15, 'Max opcode');
    assertEqual(maxDecoded.flags.rcode, 15, 'Max rcode');
    assertEqual(maxDecoded.questionCount, 0xFFFF, 'Max question count');

    // Minimum values test
    const minFlags = { qr: 0, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 0, z: 0, rcode: 0 };
    const minHeader = DNS.Encode(0x0000, minFlags, 0, 0, 0, 0);
    const minDecoded = DNS.Decode(minHeader);

    assertEqual(minDecoded.transactionId, 0, 'Min transaction ID');
    assertEqual(minDecoded.questionCount, 0, 'Min question count');

} catch (error) {
    console.log(`❌ FAIL: Edge Cases test - ${error.message}`);
    failedTests.push('Edge Cases test');
}

// ===== Test 9: Single Question Query =====
console.log('\n📝 Test 9: Single Question Query');
try {
    const singleQuestion = DNS.CreateDNSQuery(
        [{ domain: 'github.com', type: DNS.DNS_TYPES.A, class: DNS.DNS_CLASSES.IN }],
        { transactionId: 0x1111, flags: { qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, z: 0, rcode: 0 } }
    );

    const decoded = DNS.Decode(singleQuestion.slice(0, 12));
    assertEqual(decoded.questionCount, 1, 'Single question count correct');
    assertEqual(decoded.transactionId, 0x1111, 'Custom transaction ID in single question');

} catch (error) {
    console.log(`❌ FAIL: Single Question Query test - ${error.message}`);
    failedTests.push('Single Question Query test');
}

// ===== Test Results Summary =====
console.log('\n📊 Test Results Summary');
console.log('='.repeat(60));
console.log(`🧪 Total Tests Run: ${testCount}`);
console.log(`✅ Tests Passed: ${passedTests}`);
console.log(`❌ Tests Failed: ${testCount - passedTests}`);
console.log(`📈 Success Rate: ${((passedTests / testCount) * 100).toFixed(1)}%`);

if (failedTests.length > 0) {
    console.log('\n❌ Failed Tests:');
    failedTests.forEach((test, index) => {
        console.log(`   ${index + 1}. ${test}`);
    });
    console.log('\n💡 Debug your DNS functions and run tests again!');
    console.log('🔍 Check utils.js and constants.js for any missing functions.');
    process.exit(1);
} else {
    console.log('\n🎉 ALL DNS TESTS PASSED! 🚀');
    console.log('🔥 Your DNS packet builder is production-ready!');
    console.log('📡 Ready to send queries to real DNS servers!');
    process.exit(0);
}

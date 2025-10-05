// TCP Packet Builder Test Suite
// Comprehensive testing of all functionality

const TCP = require('./tcp');
const OptionBuilders = require('./option-bulder');
const Probes = require('./tcp-option-probes');
const TCPChecksum = require('./tcp-checksum');

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
    const condition = JSON.stringify(actual) === JSON.stringify(expected);
    assert(condition, testName);
    if (!condition) {
        console.log(`  Expected: ${JSON.stringify(expected)}`);
        console.log(`  Actual: ${JSON.stringify(actual)}`);
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

console.log('🧪 Starting TCP Packet Builder Test Suite\n');

// ===== Test 1: Basic SYN Packet =====
console.log('📝 Test 1: Basic SYN Packet');
try {
    const synPacket = TCP.Encode(
        '192.168.1.10', '192.168.1.20',
        40000, 80, 123456, 0,
        { syn: true }, 65535, 0,
        Buffer.alloc(0), Buffer.alloc(0)
    );

    const decoded = TCP.Decode(synPacket);

    assert(Buffer.isBuffer(synPacket), 'SYN packet is Buffer');
    assertEqual(decoded.sourcePort, 40000, 'SYN packet source port');
    assertEqual(decoded.destinationPort, 80, 'SYN packet destination port');
    assertEqual(decoded.sequenceNumber, 123456, 'SYN packet sequence number');
    assertEqual(decoded.flags, ['SYN'], 'SYN packet flags');
    assertEqual(decoded.windowSize, 65535, 'SYN packet window size');
} catch (error) {
    console.log(`❌ FAIL: Basic SYN packet test - ${error.message}`);
    failedTests.push('Basic SYN packet test');
}

// ===== Test 2: Multiple Flag Combinations =====
console.log('\n📝 Test 2: Flag Combinations');
const flagTests = [
    { flags: { fin: true }, expected: ['FIN'] },
    { flags: { syn: true, ack: true }, expected: ['SYN', 'ACK'] },
    { flags: { psh: true, ack: true }, expected: ['PSH', 'ACK'] },
    { flags: { rst: true }, expected: ['RST'] },
    { flags: { urg: true, ack: true }, expected: ['URG', 'ACK'] },
    { flags: { fin: true, ack: true }, expected: ['FIN', 'ACK'] },
    { flags: { syn: true, ece: true, cwr: true }, expected: ['SYN', 'ECE', 'CWR'] }
];

flagTests.forEach((test, index) => {
    try {
        const packet = TCP.Encode(
            '10.0.0.1', '10.0.0.2', 12345, 443,
            1000, 2000, test.flags, 8192, 0,
            Buffer.alloc(0), Buffer.alloc(0)
        );
        const decoded = TCP.Decode(packet);
        assertEqual(decoded.flags.sort(), test.expected.sort(), `Flag test ${index + 1}: ${test.expected.join('+')}`);
    } catch (error) {
        console.log(`❌ FAIL: Flag test ${index + 1} - ${error.message}`);
        failedTests.push(`Flag test ${index + 1}`);
    }
});

// ===== Test 3: Option Builders =====
console.log('\n📝 Test 3: Option Builders');
try {
    // Test MSS option
    const mssOpt = OptionBuilders.optMSS(1460);
    assertEqual(mssOpt.length, 4, 'MSS option length');
    assertEqual(mssOpt[0], 0x02, 'MSS option kind');
    assertEqual(mssOpt[1], 4, 'MSS option length field');
    assertEqual(mssOpt.readUInt16BE(2), 1460, 'MSS option value');

    // Test Window Scale option
    const wscaleOpt = OptionBuilders.optWScale(7);
    assertEqual(wscaleOpt.length, 3, 'Window Scale option length');
    assertEqual(wscaleOpt[0], 0x03, 'Window Scale option kind');
    assertEqual(wscaleOpt[2], 7, 'Window Scale option value');

    // Test SACK option
    const sackOpt = OptionBuilders.optSACK();
    assertEqual(sackOpt.length, 2, 'SACK option length');
    assertEqual(sackOpt[0], 0x04, 'SACK option kind');

    // Test Timestamp option
    const tsOpt = OptionBuilders.optTimestamp(0x12345678, 0x87654321);
    assertEqual(tsOpt.length, 10, 'Timestamp option length');
    assertEqual(tsOpt[0], 0x08, 'Timestamp option kind');
    assertEqual(tsOpt.readUInt32BE(2), 0x12345678, 'Timestamp TSval');
    assertEqual(tsOpt.readUInt32BE(6), 0x87654321, 'Timestamp TSecr');

    // Test NOP option
    const nopOpt = OptionBuilders.optNOP();
    assertEqual(nopOpt.length, 1, 'NOP option length');
    assertEqual(nopOpt[0], 0x01, 'NOP option value');

    // Test EOL option
    const eolOpt = OptionBuilders.optEOL();
    assertEqual(eolOpt.length, 1, 'EOL option length');
    assertEqual(eolOpt[0], 0x00, 'EOL option value');

} catch (error) {
    console.log(`❌ FAIL: Option builders test - ${error.message}`);
    failedTests.push('Option builders test');
}

// ===== Test 4: Options Padding =====
console.log('\n📝 Test 4: Options Padding');
try {
    // Test padding for 3-byte option (needs 1 byte padding)
    const unpadded = OptionBuilders.optWScale(3);
    const padded = OptionBuilders.optPadding(unpadded);
    assertEqual(padded.length % 4, 0, 'Padded option is 4-byte aligned');
    assertEqual(padded.length, 4, 'Window Scale padded to 4 bytes');

    // Test already aligned option (no padding needed)
    const mss = OptionBuilders.optMSS(1460);
    const mssAligned = OptionBuilders.optPadding(mss);
    assertEqual(mssAligned.length, 4, 'MSS option remains 4 bytes');
    assertBufferEqual(mss, mssAligned, 'Aligned option unchanged');

} catch (error) {
    console.log(`❌ FAIL: Options padding test - ${error.message}`);
    failedTests.push('Options padding test');
}

// ===== Test 5: Packet with Options =====
console.log('\n📝 Test 5: Packet with Options');
try {
    const options = OptionBuilders.optPadding(Buffer.concat([
        OptionBuilders.optMSS(1460),
        OptionBuilders.optWScale(7),
        OptionBuilders.optSACK(),
        OptionBuilders.optTimestamp(0xFFFFFFFF, 0)
    ]));

    const packet = TCP.Encode(
        '172.16.0.1', '172.16.0.100',
        50000, 443, 500000, 0,
        { syn: true }, 29200, 0,
        options, Buffer.alloc(0)
    );

    const decoded = TCP.Decode(packet);

    assert(decoded.options.length > 0, 'Packet has decoded options');
    assertEqual(decoded.dataOffset, Math.ceil((20 + options.length) / 4), 'Correct data offset with options');

    // Check specific options
    const mssOption = decoded.options.find(opt => opt.kind === 2);
    const wscaleOption = decoded.options.find(opt => opt.kind === 3);
    const sackOption = decoded.options.find(opt => opt.kind === 4);
    const tsOption = decoded.options.find(opt => opt.kind === 8);

    assert(mssOption !== undefined, 'MSS option found in decoded packet');
    assert(wscaleOption !== undefined, 'Window Scale option found in decoded packet');
    assert(sackOption !== undefined, 'SACK option found in decoded packet');
    assert(tsOption !== undefined, 'Timestamp option found in decoded packet');

} catch (error) {
    console.log(`❌ FAIL: Packet with options test - ${error.message}`);
    failedTests.push('Packet with options test');
}

// ===== Test 6: Packet with Data Payload =====
console.log('\n📝 Test 6: Packet with Data Payload');
try {
    const payload = Buffer.from('Hello, TCP World!', 'utf8');

    const packet = TCP.Encode(
        '10.1.1.1', '10.1.1.2',
        8080, 3000, 1000000, 2000000,
        { psh: true, ack: true }, 32768, 0,
        Buffer.alloc(0), payload
    );

    const decoded = TCP.Decode(packet);

    assertEqual(decoded.dataPayload.length, payload.length, 'Data payload length preserved');
    assertBufferEqual(decoded.dataPayload, payload, 'Data payload content preserved');
    assertEqual(decoded.flags.sort(), ['PSH', 'ACK'].sort(), 'PSH+ACK flags correct');

} catch (error) {
    console.log(`❌ FAIL: Packet with data payload test - ${error.message}`);
    failedTests.push('Packet with data payload test');
}

// ===== Test 7: Probe Configurations (Using Correct Export Names) =====
console.log('\n📝 Test 7: Probe Configurations');
const probeTests = [
    'T1_options', 'T2_options', 'T3_options', 'T4_options', 
    'T5_options', 'T6_options', 'T7_options', 'ECN_options',
    'MSS_only', 'WSCALE_only', 'SACK_only', 'TIMESTAMP_only'
];

probeTests.forEach(probeName => {
    try {
        const probeOptions = Probes[probeName];
        assert(Buffer.isBuffer(probeOptions), `${probeName} is a Buffer`);

        const packet = TCP.Encode(
            '192.168.1.1', '192.168.1.100',
            12345, 80, 1000, 0,
            { syn: true }, 65535, 0,
            probeOptions, Buffer.alloc(0)
        );

        const decoded = TCP.Decode(packet);
        assert(Buffer.isBuffer(packet), `${probeName} creates valid packet`);

    } catch (error) {
        console.log(`❌ FAIL: Probe test ${probeName} - ${error.message}`);
        failedTests.push(`Probe test ${probeName}`);
    }
});

// ===== Test 8: Additional Probe Configurations =====
console.log('\n📝 Test 8: Additional Probe Configurations');
const additionalProbes = [
    'ALL_options_v1', 'ALL_options_v2', 'UNUSUAL_MSS_1', 'UNUSUAL_MSS_2',
    'UNUSUAL_WSCALE_1', 'UNUSUAL_WSCALE_2', 'TIMESTAMP_zero', 'TIMESTAMP_small',
    'MAX_options', 'MIN_options', 'LINUX_probe', 'WINDOWS_probe', 'BSD_probe'
];

additionalProbes.forEach(probeName => {
    try {
        const probeOptions = Probes[probeName];
        if (probeOptions !== undefined) {
            assert(Buffer.isBuffer(probeOptions), `${probeName} is a Buffer`);

            const packet = TCP.Encode(
                '10.0.0.1', '10.0.0.2',
                40000, 443, 2000, 0,
                { syn: true }, 32768, 0,
                probeOptions, Buffer.alloc(0)
            );

            assert(Buffer.isBuffer(packet), `${probeName} creates valid packet`);
        } else {
            console.log(`⚠️  SKIP: ${probeName} not found in exports`);
        }

    } catch (error) {
        console.log(`❌ FAIL: Additional probe test ${probeName} - ${error.message}`);
        failedTests.push(`Additional probe test ${probeName}`);
    }
});

// ===== Test 9: Checksum Validation =====
console.log('\n📝 Test 9: Checksum Validation');
try {
    const packet1 = TCP.Encode(
        '127.0.0.1', '127.0.0.1',
        1234, 5678, 100, 200,
        { ack: true }, 1024, 0,
        Buffer.alloc(0), Buffer.alloc(0)
    );

    const packet2 = TCP.Encode(
        '127.0.0.1', '127.0.0.1',
        1234, 5678, 101, 200, // Different sequence number
        { ack: true }, 1024, 0,
        Buffer.alloc(0), Buffer.alloc(0)
    );

    const decoded1 = TCP.Decode(packet1);
    const decoded2 = TCP.Decode(packet2);

    assert(decoded1.checksum !== decoded2.checksum, 'Different packets have different checksums');
    assert(decoded1.checksum > 0, 'Checksum is non-zero');

} catch (error) {
    console.log(`❌ FAIL: Checksum validation test - ${error.message}`);
    failedTests.push('Checksum validation test');
}

// ===== Test 10: Round-trip Encoding/Decoding =====
console.log('\n📝 Test 10: Round-trip Tests');
const roundTripTests = [
    {
        name: 'Basic SYN',
        params: ['10.0.0.1', '10.0.0.2', 80, 443, 1000, 0, { syn: true }, 65535, 0, Buffer.alloc(0), Buffer.alloc(0)]
    },
    {
        name: 'FIN+ACK with high ports',
        params: ['172.16.1.1', '172.16.1.2', 65000, 65001, 4294967295, 1000000, { fin: true, ack: true }, 1024, 0, Buffer.alloc(0), Buffer.alloc(0)]
    },
    {
        name: 'RST packet',
        params: ['203.0.113.1', '203.0.113.2', 12345, 54321, 0, 0, { rst: true }, 0, 0, Buffer.alloc(0), Buffer.alloc(0)]
    }
];

roundTripTests.forEach(test => {
    try {
        const packet = TCP.Encode(...test.params);
        const decoded = TCP.Decode(packet);

        assertEqual(decoded.sourcePort, test.params[2], `${test.name}: source port round-trip`);
        assertEqual(decoded.destinationPort, test.params[3], `${test.name}: destination port round-trip`);
        assertEqual(decoded.sequenceNumber, test.params[4], `${test.name}: sequence number round-trip`);
        assertEqual(decoded.acknowledgmentNumber, test.params[5], `${test.name}: ack number round-trip`);
        assertEqual(decoded.windowSize, test.params[7], `${test.name}: window size round-trip`);
        assertEqual(decoded.urgentPointer, test.params[8], `${test.name}: urgent pointer round-trip`);

    } catch (error) {
        console.log(`❌ FAIL: Round-trip test ${test.name} - ${error.message}`);
        failedTests.push(`Round-trip test ${test.name}`);
    }
});

// ===== Test 11: Edge Cases =====
console.log('\n📝 Test 11: Edge Cases');
try {
    // Maximum values test
    const maxPacket = TCP.Encode(
        '255.255.255.255', '0.0.0.0',
        65535, 65535, 4294967295, 4294967295,
        { fin: true, syn: true, rst: true, psh: true, ack: true, urg: true, ece: true, cwr: true },
        65535, 65535, Buffer.alloc(0), Buffer.alloc(0)
    );

    const maxDecoded = TCP.Decode(maxPacket);
    assertEqual(maxDecoded.sourcePort, 65535, 'Maximum source port');
    assertEqual(maxDecoded.destinationPort, 65535, 'Maximum destination port');
    assertEqual(maxDecoded.flags.length, 8, 'All flags set');

    // Minimum values test  
    const minPacket = TCP.Encode(
        '0.0.0.0', '255.255.255.255',
        0, 0, 0, 0,
        {}, 0, 0, Buffer.alloc(0), Buffer.alloc(0)
    );

    const minDecoded = TCP.Decode(minPacket);
    assertEqual(minDecoded.sourcePort, 0, 'Minimum source port');
    assertEqual(minDecoded.destinationPort, 0, 'Minimum destination port');
    assertEqual(minDecoded.flags.length, 0, 'No flags set');

} catch (error) {
    console.log(`❌ FAIL: Edge cases test - ${error.message}`);
    failedTests.push('Edge cases test');
}

// ===== Test Results Summary =====
console.log('\n📊 Test Results Summary');
console.log('=' .repeat(50));
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

// TCP Packet Builder Test Suite
// Comprehensive testing of all functionality

const TCP = require('./tcp');
const OptionBuilders = require('../option-bulder');
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

// ===== Test 7: Probe Configurations (Using Correct Export Names) =====
console.log('\n📝 Test 7: Probe Configurations');
const probeTests = [
    'T1_options'
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

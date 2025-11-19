
const DNS = require('./dns'); // Your DNS module


function assert(condition, testName) {
    if (condition) {
        console.log(`✅ PASS: ${testName}`);
    } else {
        console.log(`❌ FAIL: ${testName}`);
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
// ===== Test 1: Basic Header Encode/Decode =====
console.log('📝 Test 1: Basic Header Encode/Decode');
const flags = { qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, z: 0, rcode: 0 };
const header = DNS.Encode(0x1234, flags, 1, 0, 0, 0);
const decoded = DNS.Decode(header);

assertEqual(header.length, 12, 'Header length is 12 bytes');
assertEqual(decoded.transactionId, 0x1234, 'Transaction ID correct');
assertEqual(decoded.flags.qr, 0, 'QR flag correct');
assertEqual(decoded.flags.rd, 1, 'RD flag correct');
assertEqual(decoded.questionCount, 1, 'Question count correct');
assertEqual(decoded.answerCount, 0, 'Answer count correct');

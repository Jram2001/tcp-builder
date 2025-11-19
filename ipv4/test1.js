const { Encode, Decode } = require('./ipv4');

const opt = Buffer.alloc(7, 0x99); // 7 bytes → needs 1 byte pad
const payload = Buffer.from('pad-test');
const pkt = Encode('10.0.0.1', '10.0.0.2', 4, 0, 0, 111, '', 0, 64, 'tcp',
    [{ type: 'RAW', data: opt }], payload);
const dec = Decode(pkt);
assertEqual(dec.IHL, 7, 'IHL 7 → 28-byte header (20 + 7 + 1 pad)');
assertEqual(dec.optionsLength, 8, 'Reported options length includes pad');


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
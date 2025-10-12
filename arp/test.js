const ARP = require('./arp'); // Your ARP module

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

console.log('🧪 Starting ARP Packet Builder Test Suite\n');

// ===== Test 1: Basic ARP Request Encoding =====
console.log('📝 Test 1: Basic ARP Request Encoding');
try {
    const arpRequest = ARP.Encode(
        1,                          // Ethernet
        0x0800,                     // IPv4
        6,                          // MAC length
        4,                          // IP length
        1,                          // Request
        "aa:bb:cc:dd:ee:ff",        // Sender MAC
        "192.168.1.100",            // Sender IP
        "00:00:00:00:00:00",        // Target MAC (unknown)
        "192.168.1.1"               // Target IP
    );

    assert(Buffer.isBuffer(arpRequest), 'ARP request is Buffer');
    assertEqual(arpRequest.length, 28, 'ARP packet length is 28 bytes');

    // Check first few bytes manually
    assertEqual(arpRequest.readUInt16BE(0), 1, 'Hardware type correct');
    assertEqual(arpRequest.readUInt16BE(2), 0x0800, 'Protocol type correct');
    assertEqual(arpRequest.readUInt8(4), 6, 'Hardware length correct');
    assertEqual(arpRequest.readUInt8(5), 4, 'Protocol length correct');
    assertEqual(arpRequest.readUInt16BE(6), 1, 'Operation (request) correct');

} catch (error) {
    console.log(`❌ FAIL: Basic ARP Request test - ${error.message}`);
    failedTests.push('Basic ARP Request test');
}

// ===== Test 2: ARP Reply Encoding =====
console.log('\n📝 Test 2: ARP Reply Encoding');
try {
    const arpReply = ARP.Encode(
        1, 0x0800, 6, 4, 2,         // Reply operation
        "11:22:33:44:55:66",        // Sender MAC
        "192.168.1.1",              // Sender IP
        "aa:bb:cc:dd:ee:ff",        // Target MAC
        "192.168.1.100"             // Target IP
    );

    assertEqual(arpReply.readUInt16BE(6), 2, 'Operation (reply) correct');
    assert(arpReply.length === 28, 'ARP reply length correct');

} catch (error) {
    console.log(`❌ FAIL: ARP Reply test - ${error.message}`);
    failedTests.push('ARP Reply test');
}

// ===== Test 3: Round-trip Encode/Decode =====
console.log('\n📝 Test 3: Round-trip Encode/Decode');
try {
    const originalData = {
        hType: 1,
        pType: 0x0800,
        hLen: 6,
        pLen: 4,
        oper: 1,
        senderMAC: "AA:BB:CC:DD:EE:FF",
        senderIP: "10.0.0.5",
        targetMAC: "00:00:00:00:00:00",
        targetIP: "10.0.0.1"
    };

    const encoded = ARP.Encode(
        originalData.hType,
        originalData.pType,
        originalData.hLen,
        originalData.pLen,
        originalData.oper,
        originalData.senderMAC,
        originalData.senderIP,
        originalData.targetMAC,
        originalData.targetIP
    );

    const decoded = ARP.Decode(encoded);

    assertEqual(decoded.hType, originalData.hType, 'Hardware type round-trip');
    assertEqual(decoded.pType, originalData.pType, 'Protocol type round-trip');
    assertEqual(decoded.hLen, originalData.hLen, 'Hardware length round-trip');
    assertEqual(decoded.pLen, originalData.pLen, 'Protocol length round-trip');
    assertEqual(decoded.oper, originalData.oper, 'Operation round-trip');
    assertEqual(decoded.senderMAC, originalData.senderMAC, 'Sender MAC round-trip');
    assertEqual(decoded.senderIP, originalData.senderIP, 'Sender IP round-trip');
    assertEqual(decoded.targetMAC, originalData.targetMAC, 'Target MAC round-trip');
    assertEqual(decoded.targetIP, originalData.targetIP, 'Target IP round-trip');

} catch (error) {
    console.log(`❌ FAIL: Round-trip test - ${error.message}`);
    failedTests.push('Round-trip test');
}

// ===== Test 4: MAC Address Formats =====
console.log('\n📝 Test 4: MAC Address Formats');
try {
    const packet1 = ARP.Encode(1, 0x0800, 6, 4, 1, "ff:ff:ff:ff:ff:ff", "255.255.255.255", "00:00:00:00:00:00", "0.0.0.0");
    const decoded1 = ARP.Decode(packet1);

    assertEqual(decoded1.senderMAC, "FF:FF:FF:FF:FF:FF", 'Broadcast MAC format correct');
    assertEqual(decoded1.senderIP, "255.255.255.255", 'Broadcast IP format correct');
    assertEqual(decoded1.targetMAC, "00:00:00:00:00:00", 'Null MAC format correct');
    assertEqual(decoded1.targetIP, "0.0.0.0", 'Zero IP format correct');

} catch (error) {
    console.log(`❌ FAIL: MAC Address formats test - ${error.message}`);
    failedTests.push('MAC Address formats test');
}

// ===== Test 5: Different Operation Codes =====
console.log('\n📝 Test 5: Different Operation Codes');
try {
    const request = ARP.Encode(1, 0x0800, 6, 4, 1, "aa:bb:cc:dd:ee:ff", "192.168.1.2", "00:00:00:00:00:00", "192.168.1.1");
    const reply = ARP.Encode(1, 0x0800, 6, 4, 2, "11:22:33:44:55:66", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.2");

    const decodedRequest = ARP.Decode(request);
    const decodedReply = ARP.Decode(reply);

    assertEqual(decodedRequest.oper, 1, 'ARP request operation code');
    assertEqual(decodedReply.oper, 2, 'ARP reply operation code');

} catch (error) {
    console.log(`❌ FAIL: Operation codes test - ${error.message}`);
    failedTests.push('Operation codes test');
}

// ===== Test 6: Private IP Ranges =====
console.log('\n📝 Test 6: Private IP Ranges');
try {
    const privateRanges = [
        { mac: "aa:bb:cc:dd:ee:01", ip: "10.1.1.1" },        // Class A private
        { mac: "aa:bb:cc:dd:ee:02", ip: "172.16.1.1" },     // Class B private
        { mac: "aa:bb:cc:dd:ee:03", ip: "192.168.1.1" }     // Class C private
    ];

    privateRanges.forEach((range, index) => {
        const packet = ARP.Encode(1, 0x0800, 6, 4, 1, range.mac, range.ip, "00:00:00:00:00:00", "8.8.8.8");
        const decoded = ARP.Decode(packet);

        assertEqual(decoded.senderMAC, range.mac.toUpperCase(), `Private range ${index + 1} MAC`);
        assertEqual(decoded.senderIP, range.ip, `Private range ${index + 1} IP`);
    });

} catch (error) {
    console.log(`❌ FAIL: Private IP ranges test - ${error.message}`);
    failedTests.push('Private IP ranges test');
}

// ===== Test 7: Edge Cases =====
console.log('\n📝 Test 7: Edge Cases');
try {
    // Maximum values
    const maxPacket = ARP.Encode(0xFFFF, 0xFFFF, 0xFF, 0xFF, 0xFFFF, "ff:ff:ff:ff:ff:ff", "255.255.255.255", "ff:ff:ff:ff:ff:ff", "255.255.255.255");
    const maxDecoded = ARP.Decode(maxPacket);

    assertEqual(maxDecoded.hType, 0xFFFF, 'Max hardware type');
    assertEqual(maxDecoded.pType, 0xFFFF, 'Max protocol type');
    assertEqual(maxDecoded.oper, 0xFFFF, 'Max operation');

    // Minimum values  
    const minPacket = ARP.Encode(0, 0, 0, 0, 0, "00:00:00:00:00:00", "0.0.0.0", "00:00:00:00:00:00", "0.0.0.0");
    const minDecoded = ARP.Decode(minPacket);

    assertEqual(minDecoded.hType, 0, 'Min hardware type');
    assertEqual(minDecoded.pType, 0, 'Min protocol type');
    assertEqual(minDecoded.oper, 0, 'Min operation');

} catch (error) {
    console.log(`❌ FAIL: Edge cases test - ${error.message}`);
    failedTests.push('Edge cases test');
}

// ===== Test 8: ARP Spoofing Scenario =====
console.log('\n📝 Test 8: ARP Spoofing Scenario');
try {
    // Legitimate ARP reply
    const legitimateReply = ARP.Encode(1, 0x0800, 6, 4, 2, "aa:bb:cc:dd:ee:ff", "192.168.1.1", "11:22:33:44:55:66", "192.168.1.100");

    // Spoofed ARP reply (attacker claiming to be gateway)
    const spoofedReply = ARP.Encode(1, 0x0800, 6, 4, 2, "99:88:77:66:55:44", "192.168.1.1", "11:22:33:44:55:66", "192.168.1.100");

    const legitDecoded = ARP.Decode(legitimateReply);
    const spoofDecoded = ARP.Decode(spoofedReply);

    assertEqual(legitDecoded.senderIP, spoofDecoded.senderIP, 'Same claimed IP');
    assert(legitDecoded.senderMAC !== spoofDecoded.senderMAC, 'Different MAC addresses (spoofing detected)');

} catch (error) {
    console.log(`❌ FAIL: ARP Spoofing scenario test - ${error.message}`);
    failedTests.push('ARP Spoofing scenario test');
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
    console.log('\n💡 Debug your ARP functions and run tests again!');
    console.log('🔍 Check utils.js for processMAC, processIP, readMAC, readIP functions.');
    process.exit(1);
} else {
    console.log('\n🎉 ALL ARP TESTS PASSED! 🚀');
    console.log('🔥 Your ARP packet builder is production-ready!');
    console.log('⚠️  Ready for network reconnaissance and security testing!');
    console.log('🛡️  Use responsibly - only on networks you own or have permission to test!');
    process.exit(0);
}

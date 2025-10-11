/**
 * DNS Constants and Record Types
 */

const DNS_TYPES = {
    A: 1,           // IPv4 address
    NS: 2,          // Name server
    CNAME: 5,       // Canonical name
    SOA: 6,         // Start of authority
    MX: 15,         // Mail exchange
    TXT: 16,        // Text record
    AAAA: 28        // IPv6 address
};

const DNS_CLASSES = {
    IN: 1,          // Internet
    CS: 2,          // CSNET
    CH: 3,          // CHAOS
    HS: 4           // Hesiod
};

const DNS_OPCODES = {
    QUERY: 0,       // Standard query
    IQUERY: 1,      // Inverse query
    STATUS: 2       // Server status
};

const DNS_RCODES = {
    NOERROR: 0,     // No error
    FORMERR: 1,     // Format error
    SERVFAIL: 2,    // Server failure
    NXDOMAIN: 3,    // Domain doesn't exist
    NOTIMP: 4,      // Not implemented
    REFUSED: 5      // Query refused
};

module.exports = { DNS_TYPES, DNS_CLASSES, DNS_OPCODES, DNS_RCODES };

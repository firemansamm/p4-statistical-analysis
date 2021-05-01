// a simple p4 switch that simply spits out 5 32 bit values in response to a single 32 bit value arriving
// with ethertype 0x88b5 (IEEE Std 802 - Local Experimental Ethertype 1).

#include <core.p4>
#include <v1model.p4>

// needed before incuding stats_freq.p4
#define STAT_FREQ_COUNTER_SIZE 600
#define STAT_FREQ_COUNTER_N 1

#include "stats_freq.p4"

#define STAT_FREQ_OFFSET (STAT_FREQ_COUNTER_SIZE >> 1)

#define TYPE_STAT 0x88b5

/* data types */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* headers */
header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
}

header val_t {
    bit<32> val;
}

header stats_h {
    stats_t stats;
}

struct headers {
    ethernet_t              ethernet;
    val_t                   val;
    stats_h                 stats;
}

struct metadata {
}


/* checksum */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}


/* ingress */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ethernet.etherType == TYPE_STAT) {
            bit<16> tmp;
            stats_push_freq(tmp, hdr.val.val + STAT_FREQ_OFFSET, 0);
            hdr.stats.setValid();
            stats_get_data(hdr.stats.stats, 0);
        }
        // Reflect packet, ignore checksums for testing - we raw packet capture on the end anyway
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = 0x123456789abc;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
}

/* egress */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/* parsing */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_STAT: extract_val;
            default: accept;
        }
    }

    state extract_val {
        packet.extract(hdr.val);
        transition accept;
    }

}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.stats);
    }
}

/* switch v1 */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
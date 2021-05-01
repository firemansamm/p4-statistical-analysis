#include <core.p4>
#include <v1model.p4>

#define STAT_FREQ_COUNTER_SIZE 30000
#define STAT_FREQ_OFFSET 15000
#define STAT_FREQ_COUNTER_N 15
#define STAT_FREQ_MAX_BEFORE_CLEAR 10

#include "stats_freq.p4"

#define BGP_DETECTION_THRESHOLD 10

#define MAX_OPTIONS         10
#define MAX_TRACKED_FLOWS   16384

#define CPU_PORT 0xFF

extern SliceExtern {
    SliceExtern();
    void slice(inout bit<32> len);
}

const bit<32>   BLOOM_FILTER_ENTRIES  = 16384;

const bit<8>    DIGEST_TYPE_LEARN   = 0x0;
const bit<8>    DIGEST_TYPE_SEQGAP  = 0x1;
const bit<8>    DIGEST_TYPE_ALLOC   = 0x2;

const bit<32>   BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;

#define TYPE_IPV4 0x800
#define PROTO_TCP  6
#define PORT_BGP 179

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

header options_t {
    varbit<320>     data;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      tos;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t   srcAddr;
    ip4Addr_t   dstAddr;
}

// IETF RFC 793 TCP, 3.1 Header Format
header tcp_t {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNo;
    bit<32>     ackNo;
    bit<4>      dataOffset;
    bit<4>      reserved;
    bit<8>      flags;
    bit<16>     window;
    bit<16>     csum;
    bit<16>     urgPtr;
}

header slice_t {
    bit<32> n;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    options_t   ipOptions;
    tcp_t       tcp;
    options_t   tcpOptions;
    slice_t     slice;
}

// L2 learning metadata

struct learn_t {
    bit<8>      digestType;
    macAddr_t   srcAddr;
    bit<9>      ingress_port;
}

struct alert_t {
    bit<8>      digestType;
    bit<32>     expected;
    bit<32>     got;
    bit<8>      ingressPrefix;
}

struct allocate_t {
    bit<8>      digestType;
    bit<8>      prefix;
}

struct metadata {
    bit<16>     tcpLen;
    bit<32>     key;
    learn_t     learn;
    alert_t     alert;
    allocate_t  alloc;
    stats_t     stats;
    bit<32>     expectedSeq;
    bit<32>     counterIdx;
    bit<32>     sliceN;
}


/* checksum */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
	    verify_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
	            hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        verify_checksum_with_payload(hdr.tcp.isValid(), 
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLen,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgPtr,
                hdr.tcpOptions
            },
            hdr.tcp.csum,
            HashAlgorithm.csum16);
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
	    update_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
	            hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

         
        // We may need to rewrite the destination port. 
        // This will invalidate the existing TCP checksum.
        update_checksum_with_payload(hdr.tcp.isValid(), 
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLen,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgPtr,
                hdr.tcpOptions
            },
            hdr.tcp.csum,
            HashAlgorithm.csum16);
    }
}


/* ingress */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* L2 switching */
    action mac_learn() {
        meta.learn.digestType = DIGEST_TYPE_LEARN;
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest(1, meta.learn);
    }

    table source {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            mac_learn;
            NoAction;
        }
        size = 256;
        default_action = mac_learn;
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dest {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    action set_mcast_grp (bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }
    table multicast {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    action allocate_counter_idx () {
        meta.alloc.digestType = DIGEST_TYPE_ALLOC;
        meta.alloc.prefix = (bit<8>)(hdr.ipv4.srcAddr >> 24);
        digest(1, meta.alloc);
    }

    action set_counter_idx (bit<32> idx) {
        meta.counterIdx = idx;
    }

    table seqprefix {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            set_counter_idx;
            allocate_counter_idx;
            NoAction;
        }
        size = 256;
        default_action = allocate_counter_idx;
    }

    /* Map the entire 4-tuple. This is (source-addr[4])(source-port[2])(dest-addr[4])(dest-port[2]). */
    /* The transport argument is not required because we only deal with TCP traffic. */
    register<bit<32>>(MAX_TRACKED_FLOWS) expectedSeq;

    apply {
        if (standard_metadata.ingress_port != CPU_PORT) source.apply();
        if (dest.apply().hit) {
            // !
        } else {
            multicast.apply();
        }

        // Redirect any BGP packet that didn't come from the CPU port (ie. not processed yet) to the CPU port.
        // Exclude BGP packets from the frequency tracking because our blackholing will definitely introduce sequence gaps.
        if ((hdr.tcp.srcPort == PORT_BGP || hdr.tcp.dstPort == PORT_BGP) && standard_metadata.ingress_port != CPU_PORT) {
            standard_metadata.egress_spec = CPU_PORT;
        }
        
        /***
         * Send a digest with the seq gap and the ingress prefix when it's non-zero.
         * We don't have that much memory, so we'll have to pick
         * a sample of (active) flows. We take MAX_TRACKED_FLOWS, and 
         * keep track of the next expected SEQ number.
         * Rather than use the entire 4-tuple, we can use ingress_prefix + hash(4-tuple)
         * to decrease collisions in the hash function (at the price of a wider key).
         * This also ensures we monitor at least a few flows per
         * peer.
         *
         * Remember that we should only apply the splice onto a target prefix
         * if that egress prefix has sent us a signal picked up on ingress (here).
         * Our goal here is to identify the prefix that is trying to tell
         * us about a splice.
         ***/
        else if (hdr.tcp.isValid()) {
            meta.key = (bit<32>)((
                (((bit<96>)hdr.ipv4.srcAddr) << 64) + 
                (((bit<96>)hdr.tcp.srcPort) << 48) + 
                (((bit<96>)hdr.ipv4.dstAddr) << 16) + 
                ((bit<96>)hdr.tcp.dstPort)
            ) % MAX_TRACKED_FLOWS);

            bit<32> payloadLen = (bit<32>)meta.tcpLen - ((bit<32>)(hdr.tcp.dataOffset) * 4);
            bit<32> nextSeq = hdr.tcp.seqNo + payloadLen;
            if ((hdr.tcp.flags & 0b1) != 0) {
                nextSeq = nextSeq + 32w1; // FIN. increments seq by 1
            }

            if ((hdr.tcp.flags & 0b10) == 0) {
                // read the expected seq and check if it matches what we got
                expectedSeq.read(meta.expectedSeq, meta.key);
                bit<32> gap = hdr.tcp.seqNo - meta.expectedSeq;
                if (gap != 0 && gap < payloadLen) {
                    meta.counterIdx = -1;
                    seqprefix.apply();

                    if (meta.counterIdx != -1) {
                        bit<16> freq;
                        stats_push_freq(freq, hdr.tcp.seqNo - meta.expectedSeq + STAT_FREQ_OFFSET, meta.counterIdx);
                        stats_get_data(meta.stats, meta.counterIdx);
                        bit<32> nx = (bit<32>)freq * meta.stats.N;

                        if (nx > (meta.stats.Xsum + meta.stats.StdNX) || (meta.stats.N == 1 && freq >= BGP_DETECTION_THRESHOLD)) {
                            meta.alert.digestType = DIGEST_TYPE_SEQGAP;
                            meta.alert.expected = meta.expectedSeq;
                            meta.alert.got = hdr.tcp.seqNo;
                            meta.alert.ingressPrefix = (bit<8>)(hdr.ipv4.srcAddr >> 24); // truncate to 8 bits for /8 prefix
                            digest(1, meta.alert);
                            stats_clear(meta.counterIdx);
                        } else if (freq >= BGP_DETECTION_THRESHOLD) {
                            stats_clear(meta.counterIdx);
                        }
                    }
                }

                if (nextSeq > meta.expectedSeq) { // can only go up: this also takes care of retransmissions
                    expectedSeq.write(meta.key, nextSeq);
                }
            } else {
                // this is a SYN.
                // the value needs to be bumped by 1.
                expectedSeq.write(meta.key, nextSeq + 32w1);
            }
        }
        
    }
}

/* egress */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    SliceExtern() slicer;
    register<bit<8>>(BLOOM_FILTER_ENTRIES) bloom_filter;

    action slice(bit<32> offset) {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)offset;
        hdr.tcp.seqNo = hdr.tcp.seqNo + offset;
        meta.sliceN = offset;

        /***
         * PROBLEM: there isn't actually a shift method 
         * as a P4 primitive. We can get around this 
         * by writing a custom extern, but it seems
         * like cheating. It may however be the only
         * way.
         * There is the option to do this in the parser:
         * it's called shift(dep)/advance, and skips
         * the next n bits in the payload. I'm not sure
         * this works inside the egress pipeline, however.
         * An idea could be to recirculate the packet with
         * the slice count inside the metadata, and then 
         * use packet.advance(meta.slice_n) when it comes back.
         * Additionally, it seems that recirculating with metadata
         * is broken at this point. We get around this by injecting
         * a header on top of the ethernet header, but this is tricky
         * because it interferes with raw traffic.
         *
         * SOLUTION: Recirculate the packet, with the slice count as
         * a header (as the metadata preservation is broken in P4_16).
         * Separate recirculated packets for slicing, and slice them
         * according to the value popped.
         * 
         * PROBLEM 2: It turns out this messes with the order of TCP packets.
         * Which is a shame, because we need them to be in order.
         * We write an extern to do this.
         ***/

    }
    table respondBgp {
        key = {
            hdr.ipv4.dstAddr: lpm; // Prefix of peer we're responding to.
        }
        actions = {
            slice;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        // We must apply the shift on a packet that contains some amount of data.
        if (hdr.tcp.isValid()) {
            bit<16> payloadSize = meta.tcpLen - ((bit<16>)(hdr.tcp.dataOffset) * 4);
            if (payloadSize > 0) { 
                bit<32> crc16;
                bit<32> crc32;

                hash(crc16, HashAlgorithm.crc16, 16w0, {
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                }, BLOOM_FILTER_ENTRIES);

                hash(crc32, HashAlgorithm.crc32, 32w0, {
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                }, BLOOM_FILTER_ENTRIES);

                bit<8> x;
                bit<8> y;
                bloom_filter.read(x, crc16);
                bloom_filter.read(y, crc32);
        
                // Check if we're sending response to this AS, only if the Bloom filter says
                // we haven't responded to this yet.
                if ((x == 0 || y == 0) && respondBgp.apply().hit) {
                    bloom_filter.write(crc16, 1);
                    bloom_filter.write(crc32, 1);
                    //recirculate({});
                    slicer.slice(meta.sliceN);
                }
            }
        }
    }
}

/* parsing */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLen = hdr.ipv4.totalLen - ((bit<16>)hdr.ipv4.ihl * 4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: options_check;
            default: accept;
        }
    }

    /***
     * Check if there are IPv4 options.
     ***/
    state options_check {
        transition select(hdr.ipv4.ihl) {
            5: tcp;
            default: options;
        }
    }

    /***
     * Extract IPv4 options into a stack.
     * We can't do anything with them, but we want to preserve them (in case someone does).
     ***/
    state options {
        packet.extract(hdr.ipOptions, (bit<32>)(((bit<16>)hdr.ipv4.ihl - 5) * 32));
        transition tcp;
    }

    state tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dataOffset) {
            4: tcp_options;
            default: accept;
        }
    }

    state tcp_options {
        packet.extract(hdr.tcpOptions, (bit<32>)(((bit<16>)hdr.tcp.dataOffset - 4) * 32));
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipOptions);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcpOptions);
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
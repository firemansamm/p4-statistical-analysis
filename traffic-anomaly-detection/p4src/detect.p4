#include <core.p4>
#include <v1model.p4>

// needed before incuding stats_freq.p4
#define STAT_FREQ_COUNTER_SIZE 50
#define STAT_FREQ_COUNTER_N 10

#include "stats_freq.p4"

// in microseconds: 2,097,152us = 2.097s ~ 2sec
// 5 windows = track for ~10 sec
#define BUCKET_SIZE 24
#define WINDOW_SIZE 2
#define STDEV_RANGE 2

// a simple L2 learning switch, with traffic anomaly detection.
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_BROADCAST = 0x1234;
const bit<8>  PROTO_TCP = 6;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header options_t {
    bit<32>     data;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

struct learn_t {
    bit<8>  digestType;
    bit<48> srcAddr;
    bit<9>  ingress_port;
}

struct alert_t {
    bit<8>  digestType;
    bit<16> last_bucket;
    bit<16> N;
    bit<32> meanNX;
    bit<32> stdevNX;
}

struct metadata {
    bit<4>      ihlRem;
    bit<4>      tcpRem;
    bit<16>     tcpLen;
    bit<32>     counter_idx;
    learn_t learn;
    alert_t alert;
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
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
    }
}


/* ingress */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(STAT_FREQ_COUNTER_N) next_bucket;
    register<bit<48>>(STAT_FREQ_COUNTER_N) last_bucket_stamp;

    action track(bit<32> counter_idx) {
        meta.counter_idx = counter_idx;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mac_learn() {
        meta.learn.digestType = 0;
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest(1, meta.learn);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dest_track {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            track;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
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

    apply {
        source.apply();
        if (dest.apply().hit) {
            // !
        } else {
            multicast.apply();
        }

        meta.counter_idx = 0xdeadbeef;
        /***
         * Ordinarily, we could have a stack of configurable tables to allow the controller
         * to assign tracking criteria here. Here, we demonstrate the concept with a single
         * table that assigns counters based on the Destination IPv4 Address field.
         ***/
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == 6) {
            dest_track.apply();
        }

        if (meta.counter_idx != 0xdeadbeef) {
            bit<48> bucket_stamp = standard_metadata.ingress_global_timestamp >> BUCKET_SIZE;
            bit<32> bucket_idx;
            next_bucket.read(bucket_idx, meta.counter_idx);

            bit<48> last_stamp;
            last_bucket_stamp.read(last_stamp, meta.counter_idx);


            if (bucket_stamp > last_stamp) {
                // read current bucket, check for threshold vs. stdev
                last_bucket_stamp.write(meta.counter_idx, bucket_stamp);

                bit<16> cval;
                read_bucket(cval, bucket_idx, meta.counter_idx);
                stats_t data;
                stats_get_data(data, meta.counter_idx);

                bit<32> nval = (bit<32>)cval * data.N;
                if (nval < data.Xsum - (STDEV_RANGE * data.StdNX) || nval > data.Xsum + (STDEV_RANGE * data.StdNX)) { // compare Nx
                    meta.alert.digestType = 1;
                    meta.alert.last_bucket = cval;
                    meta.alert.N = (bit<16>)data.N;
                    meta.alert.meanNX = data.Xsum;
                    meta.alert.stdevNX = data.StdNX;
                    digest(1, meta.alert);
                }

                // push bucket, empty bucket if needed
                bucket_idx = bucket_idx + 1;

                // check if window is full
                if (bucket_idx == WINDOW_SIZE) {
                    bucket_idx = 0;
                }
                
                // drop contents of new bucket
                drop_bucket(bucket_idx, meta.counter_idx);
                next_bucket.write(meta.counter_idx, bucket_idx);
            }
            bit<16> tmp;
            stats_push_freq(tmp, bucket_idx, meta.counter_idx);
        }
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
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        meta.ihlRem = hdr.ipv4.ihl - 4w5;
        meta.tcpLen = hdr.ipv4.totalLen - ((bit<16>)hdr.ipv4.ihl * 4);
        transition accept;
    }

}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
#include <core.p4>
#include <v1model.p4>

const bit<8>    DIGEST_TYPE_LEARN   = 0x0;

#define TYPE_IPV4 0x800
#define PROTO_TCP  6

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

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
}

// L2 learning metadata

struct learn_t {
    bit<8>      digestType;
    macAddr_t   srcAddr;
    bit<9>      ingress_port;
}


struct metadata {
    bit<16>     tcpLen;
    learn_t     learn;
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
                hdr.tcp.urgPtr
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
                hdr.tcp.urgPtr
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


    apply {
        source.apply();
        if (dest.apply().hit) {
            // !
        } else {
            multicast.apply();
        }        
    }
}

/* egress */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        
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
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: tcp;
            default: accept;
        }
    }
    
    state tcp {
        meta.tcpLen = hdr.ipv4.totalLen - ((bit<16>)hdr.ipv4.ihl * 4);
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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
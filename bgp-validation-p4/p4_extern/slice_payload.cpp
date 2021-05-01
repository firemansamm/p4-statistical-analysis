#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/packet.h>

using namespace bm;

class SliceExtern : public ExternType {
    public:
    BM_EXTERN_ATTRIBUTES {
    }

    void slice(const Data &d) {
        size_t sliceAmount = d.get<size_t>();
        Packet* pkt = &(get_packet());

        // We must have enough bytes to slice.
        if (pkt->get_payload_size() < sliceAmount) return;

        size_t newSize = pkt->get_payload_size() - sliceAmount;
        
        // Offset the payload data itself.
        char* pData = pkt->data();
        memmove(pData, pData + sliceAmount, newSize);
        pkt->set_payload_size(newSize);
    }
};

BM_REGISTER_EXTERN(SliceExtern);
BM_REGISTER_EXTERN_METHOD(SliceExtern, slice, const Data &);


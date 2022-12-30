#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <stdio.h>

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"


// MCTP packet transport header
struct mctp_header {
    nd_uint8_t ver_resv;
#define GET_MCTP_VER(v) ((v) & 0xF)
    nd_uint8_t dest_eid;
    nd_uint8_t src_eid;
    nd_uint8_t flags;
#define GET_MCTP_MSG_TAG(v) ((v) & 0x7)
#define GET_MCTP_TO(v)      (((v) >> 3) & 0x1)
#define GET_MCTP_PKT_SEQ(v) (((v) >> 4) & 0x3)
#define GET_MCTP_EOM(v)     (((v) >> 6) & 0x1)
#define GET_MCTP_SOM(v)     (((v) >> 7) & 0x1)
};

#define GET_MCTP_MSG_TYPE(v)    ((v) & 0x3f)
#define GET_MCTP_IC(v)          (((v) >> 7) & 0x1)

// Based on DMTF doc: DSP0239
#define MCTP_MSG_TYPE_CONTROL 0x00
#define MCTP_MSG_TYPE_PLDM    0x01
#define MCTP_MSG_TYPE_NVME_MI 0x04

// MCTP control message header
struct mctp_control_header {
    nd_uint8_t ic_type;
    nd_uint8_t rq_d_inst;
#define GET_MCTP_CTRL_INST(v)   ((v) & 0x1f)
#define GET_MCTP_CTRL_DBIT(v)   (((v) >> 6) & 0x1)
#define GET_MCTP_CTRL_RBIT(v)   (((v) >> 7) & 0x1)
    nd_uint8_t cmd_code;
};

#define MCTP_HEADER_SIZE (sizeof(struct mctp_header))
#define MCTP_CTRL_HEADER_SIZE (sizeof(struct mctp_control_header))

static const struct tok control_message_types[] = {
    { 0x00, "Reserved" },
    { 0x01, "Set Endpoint ID" },
    { 0x02, "Get Endpoint ID" },
    { 0x03, "Get Endpoint UUID" },
    { 0x04, "Get MCTP Version Support" },
    { 0x05, "Get Message Type Support" },
    { 0x06, "Get Vendor Defined Message Support" },
    { 0x07, "Resolve Endpoint ID" },
    { 0x08, "Allocate Endpoint IDs" },
    { 0x09, "Routing Information Update" },
    { 0x0A, "Get Routing Table Entries" },
    { 0x0B, "Prepare for Endpoint Discovery" },
    { 0x0C, "Endpoint Discovery" },
    { 0x0D, "Discovery Notify" },
    { 0x0E, "Get Network ID" },
    { 0x0F, "Query Hop" },
    { 0x10, "Resolve UUID" },
    { 0x11, "Query rate limit" },
    { 0x12, "Request TX rate limit" },
    { 0x13, "Update rate limit" },
    { 0x14, "Query Supported Interfaces" },
    { 0, NULL }
};

static const struct tok control_message_complection_codes[] = {
    { 0x00, "SUCCESS" },
    { 0x01, "ERROR" },
    { 0x02, "ERROR_INVALID_DATA" },
    { 0x03, "ERROR_INVALID_LENGTH" },
    { 0x04, "ERROR_NOT_READY" },
    { 0x05, "ERROR_UNSUPPORTED_CMD" },
    { 0, NULL }
};


static void mctp_ctrl_print(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct mctp_control_header *control = (const struct mctp_control_header*)p;
    uint8_t misc = 0;
    uint8_t comp_code = 0;
    int is_request = 0;
    ndo->ndo_protocol = "mctpctrl";
    if (caplen < MCTP_CTRL_HEADER_SIZE) {
        ND_PRINT("truncated mctpctrl %u", caplen);
        return;
    }

    misc = GET_U_1(control->rq_d_inst);
    is_request = (GET_MCTP_CTRL_RBIT(misc) == 1);
    ND_PRINT("\n\tMCTPControl: %s, IC %u, Dbit %u, Inst %u, Cmd: 0x%02x(%s)",
            (is_request ? "Request " : "Response"),
            GET_MCTP_IC(GET_U_1(control->ic_type)),
            GET_MCTP_CTRL_DBIT(misc),
            GET_MCTP_CTRL_INST(misc),
            GET_U_1(control->cmd_code),
            tok2str(control_message_types, "unknown", GET_U_1(control->cmd_code)));

    caplen -= MCTP_CTRL_HEADER_SIZE;
    p += MCTP_CTRL_HEADER_SIZE;

    if (!is_request) {
        // This is a MCTP control response message
        // print the completion code
        comp_code = GET_U_1(p);
        ND_PRINT(", CompletionCode: 0x%02x(%s)",
                comp_code,
                tok2str(control_message_complection_codes, "unknown", comp_code));
        caplen -= 1;
        p += 1;
    }

    if (!ndo->ndo_suppress_default_print)
        ND_DEFAULTPRINT(p, caplen);
}


void mctp_print(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct mctp_header *mctp = (const struct mctp_header*)p;
    uint8_t flags = 0;
    uint8_t msg_type = 0;
    const u_char *next = NULL;

    ndo->ndo_protocol = "mctp";
    if (caplen < MCTP_HEADER_SIZE) {
        ND_PRINT("truncated mctp %u", caplen);
        return;
    }

    flags = GET_U_1(mctp->flags);
    ND_PRINT("MCTP: ver %u, src_eid %u, dst_eid %u, TO %u, tag %u, seq %u, SOM %u, EOM %u, Payload %u",
            GET_MCTP_VER(GET_U_1(mctp->ver_resv)),
            GET_U_1(mctp->src_eid),
            GET_U_1(mctp->dest_eid),
            GET_MCTP_TO(flags),
            GET_MCTP_MSG_TAG(flags),
            GET_MCTP_PKT_SEQ(flags),
            GET_MCTP_SOM(flags),
            GET_MCTP_EOM(flags),
            caplen - MCTP_HEADER_SIZE);

    caplen -= MCTP_HEADER_SIZE;
    next = p + MCTP_HEADER_SIZE;

    // The upper layer message type can only be determened according to the
    // first byte of payload if the Start of Message bit is set;
    // If the SOM is not set, we just dump the remaning payload.
    if (GET_MCTP_SOM(flags)) {
        msg_type = GET_MCTP_MSG_TYPE(GET_U_1(next));
        switch (msg_type)
        {
            case MCTP_MSG_TYPE_NVME_MI:
                nvme_mi_print(ndo, next, caplen);
                break;
            case MCTP_MSG_TYPE_CONTROL:
                mctp_ctrl_print(ndo, next, caplen);
                break;
        }
    }
    else {
        if (!ndo->ndo_suppress_default_print)
            ND_DEFAULTPRINT(next, caplen);
    }
    return;
}

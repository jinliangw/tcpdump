#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <stdio.h>

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

struct nvme_mi_header {
    nd_uint8_t byte0;
#define GET_MCTP_MSG_TYPE(v)    ((v) & 0x3f)
#define GET_MCTP_IC(v)          (((v) >> 7) & 0x1)
    nd_uint8_t byte1;
#define GET_MI_CMD_SLOT(v)  (((v) >> 0) & 0x1)
#define GET_MI_TYPE(v)      (((v) >> 3) & 0xf)
#define GET_MI_RBIT(v)      (((v) >> 7) & 0x1)
    nd_uint8_t byte2;
#define GET_MI_MEB(v)       (((v) >> 0) & 0x1)
#define GET_MI_CIAP(v)      (((v) >> 1) & 0x1)
    nd_uint8_t byte3;
};

#define MI_MSG_TYPE_CTRL    0x0
#define MI_MSG_TYPE_MI      0x1
#define MI_MSG_TYPE_ADMIN   0x2
#define MI_MSG_TYPE_PCIE    0x4

#define NVME_MI_HEADER_SIZE (sizeof(struct nvme_mi_header))

struct admin_request_header {
    nd_uint8_t opcode;
    nd_uint8_t flags;
#define GET_ADMIN_DLENV(v)   (((v) >> 0) & 0x1)
#define GET_ADMIN_DOFSTV(v)  (((v) >> 1) & 0x1)
    nd_uint16_t ctrl_id;
    nd_uint32_t dw1;
    nd_uint32_t dw2;
    nd_uint32_t dw3;
    nd_uint32_t dw4;
    nd_uint32_t dw5;
    nd_uint32_t data_offset;
    nd_uint32_t data_length;
    nd_uint32_t reserved1;
    nd_uint32_t reserved2;
    nd_uint32_t dw10;
    nd_uint32_t dw11;
    nd_uint32_t dw12;
    nd_uint32_t dw13;
    nd_uint32_t dw14;
    nd_uint32_t dw15;
};

struct admin_response_header {
    nd_uint8_t status;
    nd_uint8_t rsvd1;
    nd_uint8_t rsvd2;
    nd_uint8_t rsvd3;
    nd_uint32_t dw0;
    nd_uint32_t dw1;
    nd_uint32_t dw3;
};

struct mi_cmd_request_header {
    nd_uint8_t opcode;
    nd_uint32_t dw0;
    nd_uint32_t dw1;
};

#define ADMIN_REQUEST_HEADER_SIZE (sizeof(struct admin_request_header))
#define ADMIN_RESPONSE_HEADER_SIZE (sizeof(struct admin_response_header))
#define MI_CMD_REQUEST_HEADER_SIZE (sizeof(struct mi_cmd_request_header))


static const struct tok response_message_status_values[] = {
    { 0x00, "Success" },
    { 0x01, "More Processing Required" },

    { 0x02, "Internal Error:" },
    { 0x03, "Invalid Command Opcode" },
    { 0x04, "Invalid Parameter" },
    { 0x05, "Invalid Command Size" },
    { 0x06, "Invalid Command Input Data Size" },
    { 0x07, "Access Denied" },

    { 0x20, "VPD Updates Exceeded" },
    { 0x21, "PCIe Inaccessible" },
    { 0x22, "Management Endpoint Buffer Cleared Due to Sanitize" },
    { 0x23, "Enclosure Services Failure" },
    { 0x24, "Enclosure Services Transfer Failure" },
    { 0x25, "Enclosure Failure:" },
    { 0x26, "Enclosure Services Transfer Refused" },
    { 0x27, "Unsupported Enclosure Function" },
    { 0x28, "Enclosure Services Unavailable:" },
    { 0x29, "Enclosure Degraded:" },
    { 0x2A, "Sanitize In Progress" },
    { 0, NULL }
};

static const struct tok admin_cmd_opcode_values[] = {
    { 0x00, "Delete I/O Submission Queue" },
    { 0x01, "Create I/O Submission Queue" },
    { 0x02, "Get Log Page" },
    { 0x04, "Delete I/O Completion Queue" },
    { 0x05, "Create I/O Completion Queue" },
    { 0x06, "Identify" },
    { 0x08, "Abort" },
    { 0x09, "Set Features" },
    { 0x0A, "Get Features" },
    { 0x0C, "Asynchronous Event Request" },
    { 0x0D, "Namespace Management" },
    { 0x10, "Firmware Commit" },
    { 0x11, "Firware Image Download" },
    { 0x14, "Device Self-test" },
    { 0x15, "Namespace Attachment" },
    { 0x18, "Keep Alive" },
    { 0x19, "Directive Send" },
    { 0x1A, "Directive Receive" },
    { 0x1C, "Virtualization Management" },
    { 0x1D, "NVMe-MI Send" },
    { 0x1E, "NVMe-MI Receive" },
    { 0x20, "Capacity Management" },
    { 0x24, "Lockdown" },
    { 0x7C, "Doorbell Buffer Config" },
    { 0x7F, "Fabrics Commands" },
    { 0x80, "Format NVM" },
    { 0x81, "Security Send" },
    { 0x82, "Security Receive" },
    { 0x84, "Sanitize" },
    { 0x86, "Get LBA Status" },
    { 0, NULL }
};

static const struct tok mi_cmd_opcode_values[] = {
    { 0x00, "Read NVMe-MI Data Structure" },
    { 0x01, "NVM Subsystem Health Status Poll" },
    { 0x02, "Controller Health Status Poll" },
    { 0x03, "Configuration Set" },
    { 0x04, "Configuration Get" },
    { 0x05, "VPD Read" },
    { 0x06, "VPD Write" },
    { 0x07, "Reset" },
    { 0x08, "SES Receive" },
    { 0x09, "SES Send" },
    { 0x0A, "Management Endpoint Buffer Read" },
    { 0x0B, "Management Endpoint Buffer Write" },
    { 0x0C, "Shutdown" },
    { 0, NULL }
};


static const struct tok control_primitive_opcode_values[] = {
    { 0x00, "Pause" },
    { 0x01, "Resume" },
    { 0x02, "Abort" },
    { 0x03, "Get State" },
    { 0x04, "Replay" },
    { 0, NULL }
};

static const struct tok log_page_identifies_values[] = {
    { 0x00, "Supported Log Pages" },
    { 0x01, "Error Information" },
    { 0x02, "SMART/Health Information" },
    { 0x03, "Firmware Slot Information" },
    { 0x04, "Changed Namespace List" },
    { 0x05, "Commands Supported and Effects" },
    { 0x06, "Device Self-test" },
    { 0x07, "Telemetry Host-Initiated" },
    { 0x08, "Telemetry Controller-Initiated " },
    { 0x09, "Endurance Group Information" },
    { 0x0A, "Predictable Latency Per NVM Set" },
    { 0x0B, "Predictable Latency Event Aggregate" },
    { 0x0C, "Asymmetric Namespace Access" },
    { 0x0D, "Persistent Event Log" },
    { 0x0F, "Endurance Group Event Aggregate" },
    { 0x10, "Media Unit Status" },
    { 0x11, "Supported Capacity Configuration List" },
    { 0x12, "Feature Identifiers Supported and Effects" },
    { 0x13, "NVMe-MI Commands Supported and Effects" },
    { 0x14, "Command and Feature Lockdown" },
    { 0x15, "Boot Partition" },
    { 0x16, "Rotational Media Information" },
    { 0x70, "Discovery" },
    { 0x80, "Reservation Notification" },
    { 0x81, "Sanitize Status" },
    { 0, NULL }
};

static const struct tok identify_cns_values[] = {
    { 0x00, "Identify Namespace data structure" },
    { 0x01, "Identify Controller data structure" },
    { 0x02, "Active Namespace ID list" },
    { 0x03, "Namespace Identification Descriptor list" },
    { 0x04, "NVM Set List" },
    { 0x05, "Identify Namespace data structure(I/O NSID)" },
    { 0x06, "Identify Controller data structure(I/O NSID)" },
    { 0x07, "Active Namespace ID list(I/O)" },
    { 0x08, "Independent Identify Namespace data structure(I/O)" },
    { 0x0A, "Allocated Namespace ID list" },
    { 0x0B, "Predictable Latency Event Aggregate" },
    { 0x0C, "Asymmetric Namespace Access" },
    { 0x0D, "Persistent Event Log " },
    { 0x0F, "Endurance Group Event Aggregate" },
    { 0x10, "Media Unit Status" },
    { 0x11, "Identify Namespace data structure(NSID)" },
    { 0x12, "Controller List(attached to NSID)" },
    { 0x13, "Controller List(exist in NVM)" },
    { 0x14, "Primary Controller Capabilities data structure" },
    { 0x15, "Secondary Controller list" },
    { 0x16, "Namespace Granularity list" },
    { 0x17, "UUID List" },
    { 0x18, "Domain List" },
    { 0x19, "Endurance Group List" },
    { 0x1A, "Allocated Namespace ID list(I/O)" },
    { 0x1B, "Identify Namespace data structure(I/O)" },
    { 0x1C, "I/O Command Set data structure" },
    { 0, NULL }
};


static void nvme_mi_print_get_log_page_request(netdissect_options *ndo,
        const struct admin_request_header *request)
{
    uint32_t dw10 =  GET_LE_U_4(request->dw10);
    uint32_t dw11 =  GET_LE_U_4(request->dw11);
    uint32_t dw12 =  GET_LE_U_4(request->dw12);
    uint32_t dw13 =  GET_LE_U_4(request->dw13);
    uint32_t dw14 =  GET_LE_U_4(request->dw14);

    uint64_t numd =  ((dw11 & 0xFFFF) << 16) | (dw10 >> 16);
    uint64_t lpo = ((uint64_t)dw13 << 32) | dw12;

    numd += 1; // Inc by 1 for 0's based NUMD
    ND_PRINT("\n\t          LID 0x%x(%s), LPO %llu"
            ", NUMD %lu(%llu B), RAE %u, LSP 0x%x, LSI 0x%x, CSI 0x%x, OT %u"
            ", UUIDIndex %u",
            dw10 & 0xff, // LID
            tok2str(log_page_identifies_values, "unknown", dw10 & 0xff),
            lpo,         // LPO
            numd,        // NUMD
            numd * 4,    // Dwords to bytes
            (dw10 >> 15) & 0x1, // RAE
            (dw10 >> 8) & 0x3f, // LSP
            (dw11 >> 16),       // LSI
            (dw14 >> 24),       // CSI
            (dw14 >> 23) & 0x1, // OT
            dw14 & 0x7f         // UUID Index
            );
}

static void nvme_mi_print_identify_request(netdissect_options *ndo,
        const struct admin_request_header *request)
{
    uint32_t dw10 =  GET_LE_U_4(request->dw10);
    uint32_t dw11 =  GET_LE_U_4(request->dw11);
    uint32_t dw14 =  GET_LE_U_4(request->dw14);
    ND_PRINT("\n\t          CNS 0x%x(%s), CNTID %u, CSI 0x%x"
            ", CNSID 0x%x, UUIDIndex %u",
            dw10 & 0xff,    // CNS
            tok2str(identify_cns_values, "unknown", dw10 & 0xff),
            dw10 >> 16,     // CNTID
            dw11 >> 24,     // CSI
            dw11 & 0xFFFF,  // CNS Specific Identifier
            dw14 & 0x7f     // UUID Index
            );
}

// Doesn't use dw15 as it may not be included in the current message
static void nvme_mi_print_admin_cmd_detail(netdissect_options *ndo,
        const struct admin_request_header *request)
{
    uint8_t opcode = GET_U_1(request->opcode);
    switch (opcode) {
        case 0x02:
            nvme_mi_print_get_log_page_request(ndo, request);
            break;
        case 0x06:
            nvme_mi_print_identify_request(ndo, request);
            break;
    }
}


static void nvme_mi_print_admin(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct nvme_mi_header *mi = (const struct nvme_mi_header*)p;
    uint8_t byte0 = GET_U_1(mi->byte0);
    uint8_t byte1 = GET_U_1(mi->byte1);
    uint8_t byte2 = GET_U_1(mi->byte2);
    int is_request = (GET_MI_RBIT(byte1) == 0);
    const struct admin_request_header *request = NULL;
    const struct admin_response_header *response = NULL;
    uint8_t status = 0;

    // Parses NVMe-MI header
    ND_PRINT("\n\tNVMe-MI: %s, IC %u, CmdSlot %u, type Admin, MEB %d, CIAP %u",
            is_request ? "Request " : "Response",
            GET_MCTP_IC(byte0),
            GET_MI_CMD_SLOT(byte1),
            GET_MI_MEB(byte2),
            GET_MI_CIAP(byte2));

    ndo->ndo_protocol = "NVMe-Admin";
    p += NVME_MI_HEADER_SIZE;
    caplen -= NVME_MI_HEADER_SIZE;

    if (is_request) {
        request = (const struct admin_request_header*)p;
        // Parses NVMe Admin Command Request
        // Relys on the GET_LE_U macro to detect truncated packet
        ND_PRINT("\n\tAdminReq: ");
        ND_PRINT("OP 0x%02x(%s)",
                GET_U_1(request->opcode),
                tok2str(admin_cmd_opcode_values, "unknown", GET_U_1(request->opcode)));
        ND_PRINT(", DOFSTV %u", GET_ADMIN_DOFSTV(GET_U_1(request->flags)));
        ND_PRINT(", DLENV %u",  GET_ADMIN_DLENV(GET_U_1(request->flags)));
        ND_PRINT(", CtrlID %u", GET_LE_U_2(request->ctrl_id));
        ND_PRINT(", NSIS 0x%x", GET_LE_U_4(request->dw1));
        ND_PRINT(", DW2 0x%x",  GET_LE_U_4(request->dw2));
        ND_PRINT(", DW3 0x%x",  GET_LE_U_4(request->dw3));
        ND_PRINT(", DW4 0x%x",  GET_LE_U_4(request->dw4));
        ND_PRINT(", DW5 0x%x",  GET_LE_U_4(request->dw5));
        ND_PRINT("\n\t%sDOFST %u", "          ",
                GET_LE_U_4(request->data_offset));
        ND_PRINT(", DLEN %u",   GET_LE_U_4(request->data_length));
        ND_PRINT(", DW10 0x%x", GET_LE_U_4(request->dw10));
        ND_PRINT(", DW11 0x%x", GET_LE_U_4(request->dw11));
        ND_PRINT(", DW12 0x%x", GET_LE_U_4(request->dw12));
        ND_PRINT(", DW13 0x%x", GET_LE_U_4(request->dw13));
        ND_PRINT(", DW14 0x%x", GET_LE_U_4(request->dw14));
        // The minimal MCTP pakcet size is 68B (4B MCTP header + 64B payload)
        // so it is likey that we have dw14 but no dw15, so let's check and return
        if (caplen < ADMIN_REQUEST_HEADER_SIZE)
        {
            nvme_mi_print_admin_cmd_detail(ndo, request);
            return;
        }

        ND_PRINT(", DW15 0x%x", GET_LE_U_4(request->dw15));
        p += ADMIN_REQUEST_HEADER_SIZE;
        caplen -= ADMIN_REQUEST_HEADER_SIZE;

        nvme_mi_print_admin_cmd_detail(ndo, request);
    } else {
        response = (const struct admin_response_header*)p;
        status = GET_LE_U_2(response->status);
        ND_PRINT("\n\tAdminResp: ");
        ND_PRINT("status 0x%02x(%s)",
                status,
                tok2str(response_message_status_values, "unknown", status));
        if (status == 0)
        {
            // Only print admin response message header for success response
            ND_PRINT(", DW0 0x%x", GET_LE_U_4(response->dw0));
            ND_PRINT(", DW1 0x%x", GET_LE_U_4(response->dw1));
            ND_PRINT(", DW3 0x%x", GET_LE_U_4(response->dw3));
            p += ADMIN_RESPONSE_HEADER_SIZE;
            caplen -= ADMIN_RESPONSE_HEADER_SIZE;
        }
    }

    if (!ndo->ndo_suppress_default_print) ND_DEFAULTPRINT(p, caplen);
}

static void nvme_mi_print_control(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct nvme_mi_header *mi = (const struct nvme_mi_header*)p;
    uint8_t byte0 = GET_U_1(mi->byte0);
    uint8_t byte1 = GET_U_1(mi->byte1);
    uint8_t byte2 = GET_U_1(mi->byte2);
    int is_request = (GET_MI_RBIT(byte1) == 0);
    uint8_t val = 0;

    // Parses NVMe-MI header
    ND_PRINT("\n\tNVMe-MI: %s, IC %u, CmdSlot %u, type Control",
            is_request ? "Request " : "Response",
            GET_MCTP_IC(byte0),
            GET_MI_CMD_SLOT(byte1));

    ndo->ndo_protocol = "ControlPrimitive";
    p += NVME_MI_HEADER_SIZE;
    caplen -= NVME_MI_HEADER_SIZE;

    ND_PRINT("\n\tControlPrimitive: ");
    val = GET_U_1(p);
    if (is_request)
    {
        ND_PRINT("opcode 0x%02x(%s)", val,
                tok2str(control_primitive_opcode_values, "unknown", val));
    }
    else
    {
        ND_PRINT("status 0x%02x(%s)", val,
                tok2str(response_message_status_values, "unknown", val));
    }

    ND_PRINT("tag 0x%02x", GET_U_1(p+1));
    ND_PRINT("CPSP 0x%04x", GET_LE_U_2(p+2));
    if (caplen >= 8) {
        ND_PRINT("MIC 0x%08x", GET_LE_U_4(p+2));
    }
}

static void nvme_mi_print_mi(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct nvme_mi_header *mi = (const struct nvme_mi_header*)p;
    uint8_t byte0 = GET_U_1(mi->byte0);
    uint8_t byte1 = GET_U_1(mi->byte1);
    uint8_t byte2 = GET_U_1(mi->byte2);
    int is_request = (GET_MI_RBIT(byte1) == 0);
    const struct mi_cmd_request_header *request = NULL;
    uint8_t status = 0;

    // Parses NVMe-MI header
    ND_PRINT("\n\tNVMe-MI: %s, IC %u, CmdSlot %u, type NVMe-MI, MEB %d, CIAP %u",
            is_request ? "Request " : "Response",
            GET_MCTP_IC(byte0),
            GET_MI_CMD_SLOT(byte1),
            GET_MI_MEB(byte2),
            GET_MI_CIAP(byte2));

    ndo->ndo_protocol = "NVMe-MI";
    p += NVME_MI_HEADER_SIZE;
    caplen -= NVME_MI_HEADER_SIZE;

    if (is_request) {
        request = (const struct mi_cmd_request_header*)p;
        ND_PRINT("\n\tMIReq: ");
        ND_PRINT("OP 0x%02x(%s)",
                GET_U_1(request->opcode),
                tok2str(mi_cmd_opcode_values, "unknown", GET_U_1(request->opcode)));
        ND_PRINT(", DW0 0x%x",  GET_LE_U_4(request->dw0));
        ND_PRINT(", DW1 0x%x",  GET_LE_U_4(request->dw1));
        p += MI_CMD_REQUEST_HEADER_SIZE;
        caplen -= MI_CMD_REQUEST_HEADER_SIZE;
    } else {
        status = GET_U_1(p);
        ND_PRINT("\n\tMIResp: ");
        ND_PRINT("status 0x%02x(%s)",
                status,
                tok2str(response_message_status_values, "unknown", status));
        // Dumps all response data for now.
    }

    if (!ndo->ndo_suppress_default_print) ND_DEFAULTPRINT(p, caplen);
}



void nvme_mi_print(netdissect_options *ndo, const u_char *p, u_int caplen)
{
    const struct nvme_mi_header *mi = (const struct nvme_mi_header*)p;
    uint8_t mi_msg_type = 0;

    ndo->ndo_protocol = "nvme-mi";
    if (caplen < NVME_MI_HEADER_SIZE) {
        ND_PRINT("truncated nvme-mi %u", caplen);
        return;
    }

    mi_msg_type = GET_MI_TYPE(GET_U_1(mi->byte1));
    switch (mi_msg_type) {
        case MI_MSG_TYPE_CTRL:
            nvme_mi_print_control(ndo, p, caplen);
            return;
        case MI_MSG_TYPE_MI:
            nvme_mi_print_mi(ndo, p, caplen);
            return;
        case MI_MSG_TYPE_ADMIN:
            nvme_mi_print_admin(ndo, p, caplen);
            return;
        case MI_MSG_TYPE_PCIE:
            break;
    }

    if (!ndo->ndo_suppress_default_print)
        ND_DEFAULTPRINT(p, caplen);
}

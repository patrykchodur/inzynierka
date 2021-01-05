#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#include <assert.h>

// #define DEBUG
//
// BASIC INFO FOR WIRESHARK UI
#define DISSECTOR_FULL_NAME "GEMROC Udp Data"
#define DISSECTOR_SHORT_NAME "GEMROC Udp"
#define DISSECTOR_FILTER_NAME "gemroc_udp"

#define HIGHER_LEVEL_PROTOCOL "udp"
#define PORT_NO 48350

#define MAX_DATA_COUNT 180
// packet_no (uint64), status (uint64), data_list (MAX_DATA_COUNT * uint64), data_count(uint16)
#define PACKET_SIZE (8 + 8 + MAX_DATA_COUNT*8 + 2)

// PROTOCOL HANDLE
static int proto_gemroc_udp = -1;

// PROTOCOL FIELDS HANDLES
static int hf_packet_no = -1;
static int hf_packet_status = -1;
static int hf_packet_data_list = -1;
static int hf_packet_data_count = -1;


/* STATUS */

static int hf_status_clk_state = -1;
static int hf_status_i2c_status = -1;
static int hf_status_adc_clk_sel = -1;
static int hf_status_asic_enable_status = -1;

#define STATUS_CLK_STATE_MASK               0x1F00000000000000ull
#define STATUS_I2C_STATUS_MASK              0x000F000000000000ull
#define STATUS_ADC_CLK_SEL_MASK             0x0000300000000000ull
#define STATUS_ASIC_ENABLE_STATUS_MASK      0x00000F0000000000ull

static int * status_fields[] = {
	&hf_status_clk_state,
	&hf_status_i2c_status,
	&hf_status_adc_clk_sel,
	&hf_status_asic_enable_status,
	NULL
};


/* DATA */

static int hf_data_adc = -1;
static int hf_data_timestamp_fpga = -1;
static int hf_data_timestamp_asic = -1;
static int hf_data_channel_id = -1;
static int hf_data_asic_id = -1;
static int hf_data_pile_up = -1;
static int hf_data_overflow = -1;

#define DATA_ADC_MASK                   0xFFF0000000000000ull
#define DATA_TIMESTAMP_FPGA_MASK        0x000FFFFFFFE00000ull
#define DATA_TIMESTAMP_ASIC_MASK        0x00000000001FFE00ull
#define DATA_CHANNEL_ID_MASK            0x00000000000001F0ull
#define DATA_ASIC_ID_MASK               0x000000000000000Cull
#define DATA_PILE_UP_MASK               0x0000000000000002ull
#define DATA_OVERFLOW_MASK              0x0000000000000001ull

static int * const data_fields[] = {
	&hf_data_adc,
	&hf_data_timestamp_fpga,
	&hf_data_timestamp_asic,
	&hf_data_channel_id,
	&hf_data_asic_id,
	&hf_data_pile_up,
	&hf_data_overflow,
	NULL
};

// CUSTOM DISPLAY FUNCTIONS (for bitfields)
void display_timestamp_asic(gchar *str, guint64 val) {
	snprintf(str, ITEM_LABEL_LENGTH, "%" G_GUINT64_FORMAT "", val << 2);
}
void display_asic_id(gchar *str, guint64 val) {
	snprintf(str, ITEM_LABEL_LENGTH, "%" G_GUINT64_FORMAT "", val);
}

// TREES HANDLES
static gint ett_gemroc_udp = -1;
static gint ett_gemroc_udp_data_list = -1;
static gint ett_gemroc_udp_data[180] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
static gint ett_gemroc_udp_status = -1;

#ifdef DEBUG
	#define debug_print_int(x) fprintf(stderr, "Info - " #x ": %d\n", (int)x)
	#define debug_print_str(x) fprintf(stderr, "Info - " #x ": %s\n", x)
	#define debug_print_f(...) fprintf(stderr, "Info - " __VA_ARGS__)
#else
	#define debug_print_int(x) (void)0
	#define debug_print_str(x) (void)0
	#define debug_print_f(...) (void)0
#endif // DEBUG

static int dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *top_tree_item;
	proto_tree *top_tree;
	
	proto_item *data_tree_item;
	proto_tree *data_tree;

	guint offset = 0;
	guint64 packet_no;
	guint64 data_cnt;

	// checking if the data is for us
	if (tvb_captured_length(tvb) != PACKET_SIZE) {
		debug_print_f(
				"tvb_captured_length(tvb) not equal to 8+8+%d*8+2=%d (actually %d)\n",
				MAX_DATA_COUNT,
				PACKET_SIZE,
				tvb_captured_length(tvb)
			);
		return 0;
	}

	// getting the basic info that will be used while unpacking the data
	packet_no = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
	data_cnt = (tvb_get_guint16(tvb, PACKET_SIZE - 2, ENC_LITTLE_ENDIAN) & 0xFFFF) >> 3;
	debug_print_int(packet_no);
	debug_print_int(data_cnt);


	// Preparing column info (upper window)
	col_set_str(pinfo->cinfo, COL_PROTOCOL, DISSECTOR_SHORT_NAME);
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "no: %" G_GUINT64_FORMAT ", size: %" G_GUINT64_FORMAT "", packet_no, data_cnt);

	// Registering top tree
	top_tree_item = proto_tree_add_item(tree, proto_gemroc_udp, tvb, 0, -1, ENC_NA);
	top_tree = proto_item_add_subtree(top_tree_item, ett_gemroc_udp);


	/* CONSUMING THE DATA */

	// packet no
	proto_tree_add_item(
			top_tree,
			hf_packet_no,
			tvb,
			offset,
			8,
			ENC_LITTLE_ENDIAN
		);
	offset += 8;

	// status
	proto_tree_add_bitmask(
			top_tree,
			tvb,
			offset,
			hf_packet_status,
			ett_gemroc_udp_status,
			status_fields,
			ENC_LITTLE_ENDIAN
		);
	offset += 8;

	/* DATA LIST */

	// adding label "Data list"
	data_tree_item = proto_tree_add_string_format(
			top_tree,
			hf_packet_data_list,
			tvb,
			offset,
			8*MAX_DATA_COUNT,
			ENC_NA,
			"Data list"
		);
	// making it a tree
	data_tree = proto_item_add_subtree(
			data_tree_item,
			ett_gemroc_udp_data_list
		);

	for (size_t iter = 0; iter < data_cnt; ++iter) {
		guint inner_offset = offset + (guint)iter * 8;

		char diplay_name[0x20];
		sprintf(diplay_name, "[%d]", (int)iter);

		// data (single entity)
		proto_tree_add_bitmask_text(
				data_tree,
				tvb,
				inner_offset,
				8,
				diplay_name,
				NULL,
				ett_gemroc_udp_data[iter],
				data_fields,
				ENC_LITTLE_ENDIAN,
				BMT_NO_APPEND
			);
	}
	offset += MAX_DATA_COUNT*8;

	// data count
	proto_tree_add_item(
			top_tree,
			hf_packet_data_count,
			tvb,
			offset,
			2,
			ENC_LITTLE_ENDIAN
		);
	offset += 2;

	// we should have consumed all the data
	assert(tvb_captured_length(tvb) == offset);
	return tvb_captured_length(tvb);
}

void proto_register_gemroc_udp (void)
{
	static hf_register_info hf[] = {
		/* PACKET INFO */
		{ &hf_packet_no, 
			{ "Packet no", DISSECTOR_FILTER_NAME ".pack_no", 
			  FT_UINT64, BASE_DEC, NULL, 0x0,
			  "Number of this packet", HFILL }
		},
		{ &hf_packet_status,
			{ "Status", DISSECTOR_FILTER_NAME ".status",
			  FT_UINT64, BASE_HEX, NULL, 0x0,
			  "Status containing info about asic settings", HFILL }
		},
		{ &hf_packet_data_list,
			{ "Data section", DISSECTOR_FILTER_NAME ".data_list",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "Data section of packet", HFILL }
		},
		{ &hf_packet_data_count,
			{ "Data count", DISSECTOR_FILTER_NAME ".data_cnt",
			  FT_UINT16, BASE_DEC, NULL, 0xFFF8 /* 0xFFFF >> 3 */ ,
			  "Number of data sent in this packet", HFILL }
		},

		/* STATUS INFO */
		{ &hf_status_clk_state,
			{ "Clk state", DISSECTOR_FILTER_NAME ".status.clk_st",
			  FT_UINT64, BASE_HEX, NULL, STATUS_CLK_STATE_MASK,
			  "Clk State info", HFILL }
		},
		{ &hf_status_i2c_status,
			{ "I2C status", DISSECTOR_FILTER_NAME ".status.i2c_status",
			  FT_UINT64, BASE_HEX, NULL, STATUS_I2C_STATUS_MASK,
			  "I2C status info", HFILL }
		},
		{ &hf_status_adc_clk_sel,
			{ "ADC clk sel", DISSECTOR_FILTER_NAME ".status.adc_clk_sel",
			  FT_UINT64, BASE_HEX, NULL, STATUS_ADC_CLK_SEL_MASK,
			  "ADC clk sel info", HFILL }
		},
		{ &hf_status_asic_enable_status,
			{ "ASIC enable status", DISSECTOR_FILTER_NAME ".status.asic_enable_status",
			  FT_UINT64, BASE_HEX, NULL, STATUS_ASIC_ENABLE_STATUS_MASK,
			  "ASIC enable status info", HFILL }
		},

		/* DATA INFO */
		{ &hf_data_overflow,
			{ "OverFlow", DISSECTOR_FILTER_NAME ".data.overflow",
			  FT_UINT64, BASE_DEC, NULL, DATA_OVERFLOW_MASK,
			  "OverFlow info", HFILL }
		},
		{ &hf_data_pile_up,
			{ "PileUp", DISSECTOR_FILTER_NAME ".data.pile_up",
			  FT_UINT64, BASE_DEC, NULL, DATA_PILE_UP_MASK,
			  "PileUp info", HFILL }
		},
		{ &hf_data_asic_id,
			{ "ASIC id", DISSECTOR_FILTER_NAME ".data.asic_id",
			  FT_UINT64, BASE_CUSTOM, CF_FUNC(&display_asic_id), DATA_ASIC_ID_MASK,
			  "ASIC id info", HFILL }
		},
		{ &hf_data_channel_id,
			{ "Channel id", DISSECTOR_FILTER_NAME ".data.channel_id",
			  FT_UINT64, BASE_DEC, NULL, DATA_CHANNEL_ID_MASK,
			  "Channel id info", HFILL }
		},
		{ &hf_data_timestamp_asic,
			{ "TimeStamp ASIC", DISSECTOR_FILTER_NAME ".data.ts_asic",
			  FT_UINT64, BASE_CUSTOM, CF_FUNC(&display_timestamp_asic), DATA_TIMESTAMP_ASIC_MASK,
			  "TimeStamp ASIC info", HFILL }
		},
		{ &hf_data_timestamp_fpga,
			{ "TimeStamp FPGA", DISSECTOR_FILTER_NAME ".data.ts_fpga",
			  FT_UINT64, BASE_DEC, NULL, DATA_TIMESTAMP_FPGA_MASK,
			  "TimeStamp FPGA info", HFILL }
		},
		{ &hf_data_adc,
			{ "ADC", DISSECTOR_FILTER_NAME ".data.adc",
			  FT_UINT64, BASE_DEC, NULL, DATA_ADC_MASK,
			  "ADC info", HFILL }
		},
	};

	// trees handles list
	static gint *ett[2 + 180 + 1] = {
		&ett_gemroc_udp,
		&ett_gemroc_udp_data_list
	};
	ett[182] = &ett_gemroc_udp_status;

	// add separate handles for each data element
	for (size_t iter = 0; iter < MAX_DATA_COUNT; ++iter)
		ett[iter + 2] = &ett_gemroc_udp_data[iter];

	// register protocol
	proto_gemroc_udp = proto_register_protocol (
			DISSECTOR_FULL_NAME,      /* name        */
			DISSECTOR_SHORT_NAME,     /* short name  */
			DISSECTOR_FILTER_NAME     /* filter_name */
		);

	proto_register_field_array(proto_gemroc_udp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_gemroc_udp (void)
{
	static dissector_handle_t proto_handle;

	proto_handle = create_dissector_handle(dissect, proto_gemroc_udp);
	dissector_add_uint(HIGHER_LEVEL_PROTOCOL ".port", PORT_NO, proto_handle);
}

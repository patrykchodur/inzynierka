#include "config.h"
#include <epan/packet.h>

#define PORT_NO 48350
#define DISSECTOR_FULL_NAME "PROJEKT Inzynierka"
#define DISSECTOR_NAME inz


// #define JOIN(x, y) JOIN_AGAIN(x, y)
// #define JOIN_AGAIN(x, y) x ## y
// #define PROTO_REG_HANDOFF_FUNC void JOIN(proto_reg_handoff_, DISSECTOR_NAME) (void)
// #define PROTO_REGISTER_FUNC void JOIN(proto_register_, DISSECTOR_NAME) (void)

static int proto_inz = -1;

static int hf_packet_no = -1;
static int hf_packet_additional_data = -1;
static int hf_packet_data_section = -1;
static int hf_packet_data_count = -1;

/* ADDITIONAL DATA */

static int hf_additional_data_clk_state = -1;
static int hf_additional_data_i2c_status = -1;
static int hf_additional_data_adc_clk_sel = -1;
static int hf_additional_data_asic_enable_status = -1;

#define ADDITIONAL_DATA_CLK_STATE_MASK               0x1F00000000000000ull
#define ADDITIONAL_DATA_I2C_STATUS_MASK              0x000F000000000000ull
#define ADDITIONAL_DATA_ADC_CLK_SEL_MASK             0x0000300000000000ull
#define ADDITIONAL_DATA_ASIC_ENABLE_STATUS_MASK      0x00000F0000000000ull

static int * const additional_info_fileds[] = {
	&hf_additional_data_clk_state,
	&hf_additional_data_i2c_status,
	&hf_additional_data_adc_clk_sel,
	&hf_additional_data_asic_enable_status,
	NULL
};


/* PACKET DATA */

/* Bits format GEMROC
    00-13 TimeStamp ASIC
    14-25 ADC
    26-28 ASIC id
    29    OverFlow
    30    PilUp
    31    Parity
    32-54 TimeStamp coearse (FPGA)
    55-61 Channel id
    62    Plane X/Y
    63    Parity
*/

static int hf_packet_data = -1;

static int hf_data_timestamp_asic = -1;
static int hf_data_adc = -1;
static int hf_data_asic_id = -1;
static int hf_data_overflow = -1;
static int hf_data_pilup = -1;
static int hf_data_parity_1 = -1;
static int hf_data_timestamp_coearse = -1;
static int hf_data_channel_id = -1;
static int hf_data_plane_x_y = -1;
static int hf_data_parity_2 = -1;

#define DATA_TIMESTAMP_ASIC_MASK        0x0000000000003FFFull
#define DATA_ADC_MASK                   0x0000000003FFC000ull
#define DATA_ASIC_ID_MASK               0x000000001C000000ull
#define DATA_OVERFLOW_MASK              0x0000000020000000ull
#define DATA_PILUP_MASK                 0x0000000040000000ull
#define DATA_PARITY_1_MASK              0x0000000080000000ull
#define DATA_TIMESTAMP_COEARSE_MASK     0x007FFFFF00000000ull
#define DATA_CHANNEL_ID_MASK            0x3F80000000000000ull
#define DATA_PLANE_X_Y_MASK             0x4000000000000000ull
#define DATA_PARITY_2_MASK              0x8000000000000000ull

static int * const data_fields[] = {
	&hf_data_timestamp_asic,
	&hf_data_adc,
	&hf_data_asic_id,
	&hf_data_overflow,
	&hf_data_pilup,
	&hf_data_parity_1,
	&hf_data_timestamp_coearse,
	&hf_data_channel_id,
	&hf_data_plane_x_y,
	&hf_data_parity_2,
	NULL
};

static gint ett_inz = -1;
static gint ett_inz_data = -1;
static gint ett_inz_additional_data = -1;

int printf(const char *str, ...);
int sprintf(char *, const char *, ...);

#define debug_print_int(x) printf("Info - " #x ": %d\n", (int)x)
#define debug_print_str(x) printf("Info - " #x ": %s\n", x)

static int dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *top_tree_item;
	proto_tree *top_tree;
	
	proto_item *data_tree_item;
	proto_tree *packet_tree;

	guint offset = 0;
	guint64 packet_no;
	guint64 data_cnt;

	// basic error handling
	if (tvb_captured_length(tvb) != 183 * 8) {
		printf("Error: tvb_captured_length(tvb) not equal to 183*8 (actually %d)\n", tvb_captured_length(tvb));
		return 0;
	}

	// getting some needed info
	packet_no = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
	data_cnt = (tvb_get_guint64(tvb, 182*8, ENC_LITTLE_ENDIAN) & 0xFFFF) >> 3;
	debug_print_int(packet_no);
	debug_print_int(data_cnt);


	// Preparing column info (upper window)
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Inż");
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_str(pinfo->cinfo, COL_INFO, "COL_INFO tescik");

	top_tree_item = proto_tree_add_item(tree, proto_inz, tvb, 0, -1, ENC_NA);
	top_tree = proto_item_add_subtree(top_tree_item, ett_inz);

	// packet no
	proto_tree_add_item(top_tree, hf_packet_no, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	// additional data
	proto_tree_add_bitmask(top_tree, tvb, offset, hf_packet_additional_data, ett_inz_additional_data, additional_info_fileds, ENC_LITTLE_ENDIAN);
	offset += 8;

	data_tree_item = proto_tree_add_string_format(top_tree, hf_packet_data_section, tvb, offset, 8*180, ENC_NA, "Packet list");
	packet_tree = proto_item_add_subtree(data_tree_item, ett_inz_data);
	/* consume data */
	for (size_t iter = 0; iter < data_cnt; ++iter) {
		char tab[0x20];
		guint inner_offset = offset + (guint)iter * 8;
		sprintf(tab, "Packet data[%d]", (int)iter);
		// proto_tree_add_bitmask(data_tree_item, tvb, inner_offset, hf_packet_data, ett_inz_data, data_fields, ENC_LITTLE_ENDIAN);
		proto_tree_add_bitmask_text(data_tree_item, tvb, inner_offset, 8, tab, NULL, ett_inz_data, data_fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
	}
	offset += 180*8;
	proto_tree_add_item(top_tree, hf_packet_data_count, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	return tvb_captured_length(tvb);
}

void proto_register_inz (void)
{
	static hf_register_info hf[] = {
		/* PACKET INFO */
		{ &hf_packet_no, 
			{ "Packet_no", "inz.pack_no", 
			  FT_UINT64, BASE_DEC, NULL, 0x0,
			  "Number of this packet", HFILL }
		},
		{ &hf_packet_additional_data,
			{ "Additional_data", "inz.add_data",
			  FT_UINT64, BASE_HEX, NULL, 0x0,
			  "Additional data containing info about asic settings", HFILL }
		},
		{ &hf_packet_data_section,
			{ "Data section", "inz.data_sec",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "Data section of packet", HFILL }
		},
		{ &hf_packet_data_count,
			{ "Packet_count", "inz.pack_cnt",
			  FT_UINT64, BASE_DEC, NULL, 0xFFF8 /* 0xFFFF >> 3 */ ,
			  "Number of data nodes sent in this packet", HFILL }
		},

		/* ADDITIONAL DATA INFO */
		{ &hf_additional_data_clk_state,
			{ "Clk state", "inz.add_data.clk_st",
			  FT_UINT64, BASE_HEX, NULL, ADDITIONAL_DATA_CLK_STATE_MASK,
			  "Clk State info", HFILL }
		},
		{ &hf_additional_data_i2c_status,
			{ "I2C status", "inz.add_data.i2c_status",
			  FT_UINT64, BASE_HEX, NULL, ADDITIONAL_DATA_I2C_STATUS_MASK,
			  "I2C status info", HFILL }
		},
		{ &hf_additional_data_adc_clk_sel,
			{ "ADC clk sel", "inz.add_data.adc_clk_sel",
			  FT_UINT64, BASE_HEX, NULL, ADDITIONAL_DATA_ADC_CLK_SEL_MASK,
			  "ADC clk sel info", HFILL }
		},
		{ &hf_additional_data_asic_enable_status,
			{ "ASIC enable status", "inz.add_data.asic_enable_status",
			  FT_UINT64, BASE_HEX, NULL, ADDITIONAL_DATA_ASIC_ENABLE_STATUS_MASK,
			  "ASIC enable status info", HFILL }
		},

		/* DATA INFO */
		{ &hf_packet_data,
			{ "Packet_data", "inz.pack_data",
			  FT_UINT64, BASE_HEX, NULL, 0x0,
			  "Data of packets, now unavailable", HFILL }
		},

		{ &hf_data_timestamp_asic,
			{ "TimeStamp ASIC", "inz.data.ts_asic",
			  FT_UINT64, BASE_HEX, NULL, DATA_TIMESTAMP_ASIC_MASK,
			  "TimeStamp ASIC info", HFILL }
		},
		{ &hf_data_adc,
			{ "ADC", "inz.data.adc",
			  FT_UINT64, BASE_HEX, NULL, DATA_ADC_MASK,
			  "ADC info", HFILL }
		},
		{ &hf_data_asic_id,
			{ "ASIC id", "inz.data.asic_id",
			  FT_UINT64, BASE_HEX, NULL, DATA_ASIC_ID_MASK,
			  "ASIC id info", HFILL }
		},
		{ &hf_data_overflow,
			{ "OverFlow", "inz.data.overflow",
			  FT_UINT64, BASE_HEX, NULL, DATA_OVERFLOW_MASK,
			  "OverFlow info", HFILL }
		},
		{ &hf_data_pilup,
			{ "PilUp", "inz.data.pilup",
			  FT_UINT64, BASE_HEX, NULL, DATA_PILUP_MASK,
			  "PilUp info", HFILL }
		},
		{ &hf_data_parity_1,
			{ "Parity", "inz.data.parity_1",
			  FT_UINT64, BASE_HEX, NULL, DATA_PARITY_1_MASK,
			  "Parity info", HFILL }
		},
		{ &hf_data_timestamp_coearse,
			{ "TimeStamp coearse (FPGA)", "inz.data.ts_coearse",
			  FT_UINT64, BASE_HEX, NULL, DATA_TIMESTAMP_COEARSE_MASK,
			  "TimeStamp coearse (FPGA) info", HFILL }
		},
		{ &hf_data_channel_id,
			{ "Channel id", "inz.data.channel_id",
			  FT_UINT64, BASE_HEX, NULL, DATA_CHANNEL_ID_MASK,
			  "Channel id info", HFILL }
		},
		{ &hf_data_plane_x_y,
			{ "Plane X/Y", "inz.data.plane_x_y",
			  FT_UINT64, BASE_HEX, NULL, DATA_PLANE_X_Y_MASK,
			  "Plane X/Y info", HFILL }
		},
		{ &hf_data_parity_2,
			{ "Parity 2", "inz.data.parity_2",
			  FT_UINT64, BASE_HEX, NULL, DATA_PARITY_2_MASK,
			  "Parity 2 info", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_inz,
		&ett_inz_data,
		&ett_inz_additional_data,
	};

	proto_inz = proto_register_protocol (
			"PROJEKT Inzynierka",    /* name        */
			"INZ",                   /* short name  */
			"inz"                    /* filter_name */
			);

	proto_register_field_array(proto_inz, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_inz (void)
{
	static dissector_handle_t guide_handle;

	guide_handle = create_dissector_handle(/*the dissection function*/ dissect, proto_inz);
	dissector_add_uint("udp.port", PORT_NO, guide_handle);
}

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

/* forward reference */
void proto_register_minecraft();
void proto_reg_handoff_minecraft();
void dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Define version if we are not building Wireshark statically */
#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = "0.0";
#endif

#define PROTO_TAG_MC "MC"

static int proto_minecraft = -1;
static dissector_handle_t minecraft_handle;

static const value_string packettypenames[] = {
      { 0x00, "Keep Alive" },
      { 0x01, "Login" },
      { 0x02, "Handshake" },
      { 0x03, "Chat" },
      { 0x04, "Update Time" },
      { 0x0A, "Unknown(0x0A)" },
      { 0x0B, "Player Position" },
      { 0x0C, "Player Look" },
      { 0x0D, "Player Move + Look" },
      { 0x0E, "Block Dig" },
      { 0x0F, "Place" },
      { 0x10, "Block/Item Switch" },
      { 0x11, "Add to Inventory" },
      { 0x12, "Arm Animation" },
      { 0x14, "Named Entity Spawn" },
      { 0x15, "Entity Spawn" },
      { 0x16, "Collect Item" },
      { 0x17, "Unknown(0x17)" },
      { 0x18, "Mob Spawn" },
      { 0x1D, "Destroy Entity" },
      { 0x1E, "Entity" },
      { 0x1F, "Relative Entity Move" },
      { 0x20, "Entity Look" },
      { 0x21, "Relative Entity Move + Look" },
      { 0x22, "Entity Teleport" },
      { 0x32, "Pre-Chunk" },
      { 0x33, "Map Chunk" },
      { 0x34, "Multi Block Change" },
      { 0x35, "Block Change" },
      { 0xFF, "Kick" },
      { 0, NULL }
};

#ifndef ENABLE_STATIC
G_MODULE_EXPORT void plugin_register(void)
{
    /* register the new protocol, protocol fields, and subtrees */
    if (proto_minecraft == -1) { /* execute protocol initialization only once */
        proto_register_minecraft();
    }
}

G_MODULE_EXPORT void plugin_reg_handoff(void) {
    proto_reg_handoff_minecraft();
}
#endif

static int ett_minecraft = -1;

/* Setup protocol subtree array */
static int *ett[] = {
    &ett_minecraft
};

void proto_register_minecraft(void)
{
    module_t *module;

    if (proto_minecraft == -1)
    {
        proto_minecraft = proto_register_protocol (
                              "Minecraft Alpha SMP Protocol", /* name */
                              "Minecraft",          /* short name */
                              "mc"	         /* abbrev */
                          );

        module = prefs_register_protocol(proto_minecraft, proto_reg_handoff_minecraft);
        proto_register_subtree_array(ett, array_length(ett));

    }
}

void proto_reg_handoff_minecraft(void)
{
    static int Initialized=FALSE;

    /* register with wireshark to dissect udp packets on port 3001 */
    if (!Initialized) {
        minecraft_handle = create_dissector_handle(dissect_minecraft, proto_minecraft);
        dissector_add("tcp.port", 25565, minecraft_handle);
    }
}

static void dissect_minecraft_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int type;
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MC);
    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo,COL_INFO)){
        col_clear(pinfo->cinfo,COL_INFO);
    }
    type = tvb_get_guint8( tvb, 0 ); // Get the type byte

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Info Type:[%s]",
            pinfo->srcport, pinfo->destport, 
            val_to_str(type, packettypenames, "Unknown Type:0x%02x"));
    }


}
guint get_minecraft_packet_len(guint8 type,guint offset, guint available, tvbuff_t *tvb) {
	guint len=-1;
	switch(type) {
		case 0x00:
			len = 1;
			break;
		case 0x01:
			{
				int len_strA, len_strB;
				if ( available >= 7 ) {
					len_strA = tvb_get_ntohs(tvb, offset + 5);
					if ( available >= 9 + len_strA ) {
						len_strB = tvb_get_ntohs(tvb, offset + 7 + len_strA);
						len = 5 + (2 + len_strA) + (2 + len_strB);
					}
				}
			}
			break;
		case 0x02:
			if ( available >= 3 ) {
				len = 3 + tvb_get_ntohs(tvb, offset + 1);
			}
			break;
		case 0x03:
			if ( available >= 3 ) {
				len = 3 + tvb_get_ntohs(tvb, offset + 1);
			}
			break;
		case 0x04:
			len = 9;
			break;
		case 0x0A:
			len = 2;
			break;
		case 0x0B:
			len = 34;
			break;
		case 0x0C:
			len = 10;
			break;
		case 0x0D:
			len = 42;
			break;
		case 0x0E:
			len = 12;
			break;
		case 0x15:
			len = 23;
			break;
		case 0x18:
			len = 20;
			break;
		case 0x1D:
			len = 5;
			break;
		case 0x1E:
			len = 5;
			break;
		case 0x1F:
			len = 8;
			break;
		case 0x20:
			len = 7;
			break;
		case 0x21:
			len = 10;
			break;
		case 0x22:
			len = 19;
			break;
		case 0x32:
			len = 10;
			break;
		case 0x33:
			if ( available >= 18 ) {
				len = 18 + tvb_get_ntohl(tvb, offset + 14);
			}
			break;
		case 0x34:
			if ( available >= 11 ) {
				// the size we get here is number of elements in the arrays
				// and there are 3 arrays, a short, and two bytes, so multiply by 4
            	len = 11 + (4 * tvb_get_ntohs(tvb, offset + 9));
			}
			break;
		case 0x35:
			len = 12;
			break;
		case 0xff:
			if ( available >= 3 ) {
            	len = 3 + tvb_get_ntohs(tvb, offset + 1);
			}
			break;
		default:
			printf("Unknown packet: 0x%x\n", type);
			len = -1;
	}
	return len;

}

#define FRAME_HEADER_LEN 17
void dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 packet;
	guint offset=0;

	while(offset < tvb_reported_length(tvb)) {
    	packet = tvb_get_guint8(tvb, offset);
    	gint available = tvb_reported_length_remaining(tvb, offset);
		gint len = get_minecraft_packet_len(packet, offset, available, tvb);
		if (len == -1 || len >= available) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
		dissect_minecraft_message(tvb, pinfo, tree);
    	offset += len;
	}
}


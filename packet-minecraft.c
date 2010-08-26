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
      { 0, "Keep Alive" },
      { 1, "Login" },
      { 2, "Handshake" },
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
    printf("Disecting message!\n");
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

static guint get_minecraft_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    int packet;
    guint len=0;

    packet = tvb_get_guint8(tvb, 0);
    switch(packet) {
      case 0x00:
        len = 1;
        break;
      case 0x01:
        {
          int len_strA, len_strB;
          len_strA = tvb_get_ntohs(tvb, 5);
          len_strB = tvb_get_ntohs(tvb, 7 + len_strA);
          len = 5 + (2 + len_strA) + (2 + len_strB);
        }
        break;
      case 0x02:
        len = 3 + tvb_get_ntohs(tvb, 1);
        break;
      case 0x03:
        len = tvb_get_ntohs(tvb,1);
        break;
      case 0x04:
        len = 5;
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
      /* ... */
      case 0x32:
        len = 10;
        break;
      case 0x33:
        len = tvb_get_ntohs(tvb, 14) + 14;
        break;
    }
    gint rest = tvb_reported_length_remaining(tvb, len);
    if (rest != 0) {
        pinfo->desegment_offset = len;
        pinfo->desegment_len = rest;
    }
    printf("Packet: 0x%x Offset: %d Len: %d Rest: %d\n", packet, offset, len, rest);
    return len;

}
#define FRAME_HEADER_LEN 17
void dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_minecraft_message_len, dissect_minecraft_message);
}


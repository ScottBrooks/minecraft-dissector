/* Copyright (C) 2011 by Scott Brooks

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

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

proto_item *mc_item = NULL;
proto_item *mc_sub_item = NULL;
proto_tree *mc_tree = NULL;
proto_tree *mc_header_tree = NULL;

static const value_string packettypenames[] = {
    { 0x00, "Keep Alive" },
    { 0x01, "Login" },
    { 0x02, "Handshake" },
    { 0x03, "Chat" },
    { 0x04, "Update Time" },
    { 0x05, "Inventory" },
    { 0x06, "Compass Target"},
    { 0x07, "Unknown(1.2.2) 0x07"},
    { 0x0A, "Player on ground" },
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
    { 0x1C, "Unknown(1.2.2) 0x1C"},
    { 0x1D, "Destroy Entity" },
    { 0x1E, "Entity" },
    { 0x1F, "Relative Entity Move" },
    { 0x20, "Entity Look" },
    { 0x21, "Relative Entity Move + Look" },
    { 0x22, "Entity Teleport" },
    { 0x27, "Unknown(1.2.2) 0x27" },
    { 0x32, "Pre-Chunk" },
    { 0x33, "Map Chunk" },
    { 0x34, "Multi Block Change" },
    { 0x35, "Block Change" },
    { 0x3b, "Complex Entity"},
    { 0xFF, "Kick" },
    { 0, NULL }
};

static const value_string directionnames[] = {
    {0, "-Y"},
    {1, "+Y"},
    {2, "-Z"},
    {3, "+Z"},
    {4, "-X"},
    {5, "+X"},
    {0, NULL}
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

static int ett_mc = -1;

/* Setup protocol subtree array */
static int *ett[] = {
    &ett_mc
};
static gint hf_mc_data = -1;
static gint hf_mc_type = -1;
static gint hf_mc_server_name = -1;
static gint hf_mc_motd = -1;
static gint hf_mc_username = -1;
static gint hf_mc_password = -1;
static gint hf_mc_serverid = -1;
static gint hf_mc_handshake_username = -1;
static gint hf_mc_chat = -1;
static gint hf_mc_time = -1;
static gint hf_mc_loaded = -1;
static gint hf_mc_x = -1;
static gint hf_mc_y = -1;
static gint hf_mc_z = -1;
static gint hf_mc_xbyte = -1;
static gint hf_mc_ybyte = -1;
static gint hf_mc_zbyte = -1;
static gint hf_mc_stance = -1;
static gint hf_mc_rotation = -1;
static gint hf_mc_pitch = -1;
static gint hf_mc_status = -1;
static gint hf_mc_yshort = -1;
static gint hf_mc_dig = -1;
static gint hf_mc_block_type = -1;
static gint hf_mc_direction = -1;
static gint hf_mc_xint = -1;
static gint hf_mc_yint = -1;
static gint hf_mc_zint = -1;
static gint hf_mc_unique_id = -1;
static gint hf_mc_unknown_byte = -1;
static gint hf_mc_rotation_byte = -1;
static gint hf_mc_pitch_byte = -1;
static gint hf_mc_size_x = -1;
static gint hf_mc_size_y = -1;
static gint hf_mc_size_z = -1;
static gint hf_mc_block_type_byte = -1;
static gint hf_mc_block_meta_byte = -1;
static gint hf_mc_item_code = -1;
static gint hf_mc_amount = -1;
static gint hf_mc_life = -1;

void proto_register_minecraft(void)
{
    module_t *module;

    if (proto_minecraft == -1)
    {
        static hf_register_info hf[] = {
            { &hf_mc_data,
                {"Data", "mc.data", FT_NONE, BASE_NONE, NULL, 0x0, "Packet Data", HFILL}
            },
            { &hf_mc_type,
              { "Type", "mc.type", FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0, "Packet Type", HFILL }
            },
            { &hf_mc_server_name,
              {"Server Name", "mc.server_name", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_motd,
              {"MOTD", "mc.motd", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_username,
              {"Username", "mc.username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_password,
              {"Password", "mc.password", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_serverid,
              {"Server ID", "mc.server_id", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_handshake_username,
              {"Handshake Username", "mc.handshake_username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_chat,
              {"Chat", "mc.chat", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_time,
              {"Time", "mc.time", FT_INT64, BASE_DEC, NULL, 0x0, "Update Time", HFILL }
            },
            { &hf_mc_loaded,
              {"Loaded", "mc.loaded", FT_BOOLEAN, BASE_DEC, NULL, 0x0, "Loaded", HFILL }
            },
            { &hf_mc_x,
              {"X", "mc.x", FT_DOUBLE, BASE_DEC, NULL, 0x0, "X Coord", HFILL }
            },
            { &hf_mc_y,
              {"Y", "mc.y", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_z,
              {"Z", "mc.z", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Z Coord", HFILL }
            },
            { &hf_mc_stance,
              {"Stance", "mc.stance", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Stance", HFILL }
            },
            { &hf_mc_rotation,
              {"Rotation", "mc.rotation", FT_FLOAT, BASE_DEC, NULL, 0x0, "Rotation", HFILL }
            },
            { &hf_mc_pitch,
              {"Pitch", "mc.pitch", FT_FLOAT, BASE_DEC, NULL, 0x0, "Pitch", HFILL }
            },
            { &hf_mc_status,
              {"Status", "mc.status", FT_INT8, BASE_DEC, NULL, 0x0, "Status", HFILL }
            },
            { &hf_mc_xbyte,
              {"X", "mc.xbyte", FT_INT8, BASE_DEC, NULL, 0x0, "X Offset", HFILL }
            },
            { &hf_mc_ybyte,
              {"Y", "mc.ybyte", FT_INT8, BASE_DEC, NULL, 0x0, "Y Offset", HFILL }
            },
            { &hf_mc_zbyte,
              {"Z", "mc.zbyte", FT_INT8, BASE_DEC, NULL, 0x0, "Z Offset", HFILL }
            },
            { &hf_mc_yshort,
              {"Y", "mc.yshort", FT_INT16, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_dig,
              {"Dig", "mc.dig", FT_INT8, BASE_DEC, NULL, 0x0, "Digging/Stopped/Broken", HFILL }
            },
            { &hf_mc_block_type,
              {"Block/Item Type", "mc.block_type", FT_INT16, BASE_DEC, NULL, 0x0, "Block/Item Type", HFILL }
            },
            { &hf_mc_direction,
              {"Direction", "mc.direction", FT_INT8, BASE_DEC, VALS(directionnames), 0x0, "Direction", HFILL }
            },
            { &hf_mc_xint,
              {"X", "mc.xint", FT_INT32, BASE_DEC, NULL, 0x0, "X Coord", HFILL }
            },
            { &hf_mc_yint,
              {"Y", "mc.yint", FT_INT32, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_zint,
              {"Z", "mc.zint", FT_INT32, BASE_DEC, NULL, 0x0, "Z Coord", HFILL }
            },
            { &hf_mc_unique_id,
              {"Unique ID", "mc.unique_id", FT_INT32, BASE_DEC, NULL, 0x0, "Unique ID", HFILL }
            },
            { &hf_mc_unknown_byte,
              {"Unknown Byte", "mc.unknown_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Unknown Byte", HFILL }
            },
            { &hf_mc_rotation_byte,
              {"Rotation Byte", "mc.rotation_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Rotation Byte", HFILL }
            },
            { &hf_mc_pitch_byte,
              {"Pitch", "mc.pitch_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Pitch Byte", HFILL }
            },
            { &hf_mc_size_x,
              {"Size X", "mc.size_x", FT_INT8, BASE_DEC, NULL, 0x0, "X Size", HFILL }
            },
            { &hf_mc_size_y,
              {"Size Y", "mc.size_y", FT_INT8, BASE_DEC, NULL, 0x0, "Y Size", HFILL }
            },
            { &hf_mc_size_z,
              {"Size Z", "mc.size_z", FT_INT8, BASE_DEC, NULL, 0x0, "Z Size", HFILL }
            },
            { &hf_mc_block_type_byte,
              {"Block/Item Type", "mc.block_type_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Block/Item Type", HFILL }
            },
            { &hf_mc_block_meta_byte,
              {"Block Metadata", "mc.block_meta_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Block Metadata", HFILL }
            },
            { &hf_mc_item_code,
              {"Item Code", "mc.item_code", FT_INT16, BASE_DEC, NULL, 0x0, "Item Code", HFILL }
            },
            { &hf_mc_amount,
              {"Amount", "mc.amount", FT_INT8, BASE_DEC, NULL, 0x0, "Amount", HFILL }
            },
            { &hf_mc_life,
              {"Life", "mc.life", FT_INT16, BASE_DEC, NULL, 0x0, "Life", HFILL }
            },

        };
        proto_minecraft = proto_register_protocol (
                              "Minecraft Alpha SMP Protocol", /* name */
                              "Minecraft",          /* short name */
                              "mc"	         /* abbrev */
                          );

        module = prefs_register_protocol(proto_minecraft, proto_reg_handoff_minecraft);

        proto_register_field_array(proto_minecraft, hf, array_length(hf));
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

static void add_login_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint16 strlen1, strlen2;

    strlen1 = tvb_get_ntohs( tvb, offset + 5 );
    proto_tree_add_item(tree, hf_mc_server_name, tvb, offset + 5, strlen1, FALSE);

    strlen2 = tvb_get_ntohs( tvb, offset + 5 + strlen1 + 2 );
    proto_tree_add_item(tree, hf_mc_motd, tvb, offset + 5 + strlen1 + 2, strlen2, FALSE);
}
static void add_handshake_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint16 strlen1;

    strlen1 = tvb_get_ntohs( tvb, offset + 1 );
    proto_tree_add_item(tree, hf_mc_serverid, tvb, offset + 3, strlen1, FALSE);
}
static void add_chat_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint16 strlen1;

    strlen1 = tvb_get_ntohs( tvb, offset + 1 );
    proto_tree_add_item(tree, hf_mc_chat, tvb, offset + 3, strlen1, FALSE);
}
static void add_time_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint64 time;

    time = tvb_get_ntoh64(tvb, offset + 1 );
    proto_tree_add_item(tree, hf_mc_time, tvb, offset + 1, 8, FALSE);
}
static void add_loaded_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_loaded, tvb, offset + 1, 1, FALSE);
}
static void add_player_position_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{

    /*
    gdouble x,y,z,s;
    x = tvb_get_gdouble(tvb, offset + 1);
    y = tvb_get_gdouble(tvb, offset + 9);
    s = tvb_get_gdouble(tvb, offset + 17);
    z = tvb_get_gdouble(tvb, offset + 25);
      */
    proto_tree_add_item(tree, hf_mc_x, tvb, offset + 1, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_y, tvb, offset + 9, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_stance, tvb, offset + 17, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_z, tvb, offset + 25, 8, FALSE);

}
static void add_player_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{

    proto_tree_add_item(tree, hf_mc_rotation, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch, tvb, offset + 5, 4, FALSE);

}
static void add_player_move_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_x, tvb, offset + 1, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_y, tvb, offset + 9, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_stance, tvb, offset + 17, 8, FALSE);
    proto_tree_add_item(tree, hf_mc_z, tvb, offset + 25, 8, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation, tvb, offset + 33, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch, tvb, offset + 37, 4, FALSE);

}
static void add_block_dig_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_status, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 2, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_direction, tvb, offset + 11, 1, FALSE);

}
static void add_place_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 1, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 3, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 8, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_direction, tvb, offset + 12, 1, FALSE);

}
static void add_block_item_switch_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_item_code, tvb, offset + 5, 2, FALSE);
}
static void add_add_to_inventory_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 1, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_amount, tvb, offset + 3, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_life, tvb, offset + 4, 2, FALSE);
}
static void add_arm_animation_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_unknown_byte, tvb, offset + 5, 1, FALSE);
}
static void add_named_entity_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    int name_len, o2;
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    name_len = tvb_get_ntohs(tvb, offset + 5);
    proto_tree_add_item(tree, hf_mc_username, tvb, offset + 7, name_len, FALSE);

    o2 = offset + 7 + name_len;
    proto_tree_add_item(tree, hf_mc_xint, tvb, o2, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, o2 + 4, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, o2 + 8, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, o2 + 12, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, o2 + 13, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_item_code, tvb, o2 + 14, 2, FALSE);


}
static void add_pickup_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{

    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_unknown_byte, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 8, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, offset + 12, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 16, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 20, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 21, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_unknown_byte, tvb, offset + 22, 1, FALSE);
}
static void add_pre_chunk_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 5, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 9, 1, FALSE);
}
static void add_map_chunk_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yshort, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_size_x, tvb, offset + 11, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_size_y, tvb, offset + 12, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_size_z, tvb, offset + 13, 1, FALSE);

}
static void add_block_change_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 6, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_block_type_byte, tvb, offset + 10, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_block_meta_byte, tvb, offset + 11, 1, FALSE);

}
static void add_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, offset + 5, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 9, 4, FALSE);
}

static void add_complex_entity_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yshort, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);

}
static void add_collect_item_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);
}
static void add_object_vehicle_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_type, tvb, offset + 5, 1, FALSE);

    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 6, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, offset + 10, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 14, 4, FALSE);
}
static void add_destroy_entity_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
}
static void add_relative_entity_move_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);

}
static void add_entity_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 6, 1, FALSE);

}
static void add_relative_entity_move_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 8, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 9, 1, FALSE);

}

static void dissect_minecraft_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 type,  guint32 offset, guint32 length)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MC);
    /* Clear out stuff in the info column */
//    if(check_col(pinfo->cinfo,COL_INFO)){
//        col_clear(pinfo->cinfo,COL_INFO);
//    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, pinfo->match_port == pinfo->destport ? "C->S" : "S->C" ": %d > %d Info Type:[%s]",
                     pinfo->srcport, pinfo->destport,
                     val_to_str(type, packettypenames, "Unknown Type:0x%02x"));
    }
    if ( tree ) {
        mc_item = proto_tree_add_item(tree, proto_minecraft, tvb, offset, length, FALSE);
        mc_tree = proto_item_add_subtree(mc_item, ett_mc);

        proto_tree_add_item(mc_tree, hf_mc_type, tvb, offset, 1, FALSE);
        proto_tree_add_item(mc_tree, hf_mc_data, tvb, offset, length, FALSE);
        switch (type) {
        case 0x01:
            add_login_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x02:
            add_handshake_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x03:
            add_chat_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x04:
            add_time_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x06:
            add_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0A:
            add_loaded_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0B:
            add_player_position_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0C:
            add_player_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0D:
            add_player_move_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0E:
            add_block_dig_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0F:
            add_place_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x10:
            add_block_item_switch_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x11:
            add_add_to_inventory_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x12:
            add_arm_animation_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x14:
            add_named_entity_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x15:
            add_pickup_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x16:
            add_collect_item_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x17:
            add_object_vehicle_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x1D:
            add_destroy_entity_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x1F:
            add_relative_entity_move_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x20:
            add_entity_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x21:
            add_relative_entity_move_look_details(mc_tree, tvb, pinfo, offset);
            break;
            /* ... */
        case 0x32:
            add_pre_chunk_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x33:
            add_map_chunk_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x35:
            add_block_change_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x3b:
            add_complex_entity_details(mc_tree, tvb, pinfo, offset);
            break;
        }
    }
}

guint get_minecraft_packet_len(guint8 type,guint offset, guint available, tvbuff_t *tvb) {
    guint len=-1;
    switch (type) {
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
                len = 5 + (2 + len_strA) + (2 + len_strB) + 9;
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
    case 0x05:
    {
        if ( available >= 7 ) {
            int num_inv, o, size, count;
            gint16 val;
            num_inv = tvb_get_ntohs(tvb, offset + 5);
            o = offset + 7;
            size = 0;
            count = 0;
            while ( o-offset < available && available -(o-offset) >= 2 && count != num_inv ) {
                count++;

                val = tvb_get_ntohs(tvb, o);
                if ( val == -1 ) {
                    size += 2;
                    o += 2;
                } else {
                    size += 5;
                    o += 5;
                }
            }
            if ( count == num_inv ) {
                len = 7 + size;
            }
        }
    }
    break;
    case 0x06:
        len = 13;
        break;
    case 0x0A:
        len = 2;
        break;
    case 0x0B:
        len = 34;
        break;
    case 0x07:
        len = 9;
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
    case 0x0F:
        len = 13;
        break;
    case 0x10:
        len = 7;
        break;
    case 0x11:
        len = 6;
        break;
    case 0x12:
        len = 6;
        break;
    case 0x15:
        len = 23;
        break;
    case 0x16:
        len = 9;
        break;
    case 0x17:
        len = 18;
        break;
    case 0x18:
        len = 20;
        break;
    case 0x1C:
        len = 11;
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
    case 0x27:
        len = 9;
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
    case 0x3b:
        if ( available >= 13 ) {
            len = 13 + tvb_get_ntohs(tvb, offset + 11);
        }
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

    while (offset < tvb_reported_length(tvb)) {
        packet = tvb_get_guint8(tvb, offset);
        gint available = tvb_reported_length_remaining(tvb, offset);
        gint len = get_minecraft_packet_len(packet, offset, available, tvb);
        if (len == -1 || len > available) {
            pinfo->desegment_offset = offset;
            if ( len == -1 ) {
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            } else {
                pinfo->desegment_len = len - available;
            }
            return;
        }
        dissect_minecraft_message(tvb, pinfo, tree, packet, offset, len);
        offset += len;
    }
}


-- MIT License

-- Copyright (c) 2019 TAIT & VYV Corporation

-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the "Software"),
-- to deal in the Software without restriction, including without limitation
-- the rights to use, copy, modify, merge, publish, distribute, sublicense,
-- and/or sell copies of the Software, and to permit persons to whom the
-- Software is furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
-- EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-- MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-- IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
-- CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
-- TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
-- SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-- Copy the Lua dissector file to the Wireshark personal plugins folder.
-- Find this folder by looking in Help > About Wireshark > folders > Personal Lua Plugins
-- You may need to create this folder.

local p_psn = Proto("psn","PosiStageNet")

local PSN_INFO_PACKET = 0x6756
local PSN_DATA_PACKET = 0x6755
local PSN_V1_INFO_PACKET = 0x503c
local PSN_V1_DATA_PACKET = 0x6754

local BASE_CHUNK_IDS = {
    [PSN_INFO_PACKET] = "PSN_V2_INFO_PACKET",
    [PSN_DATA_PACKET] = "PSN_V2_DATA_PACKET",
    [PSN_V1_INFO_PACKET] = "PSN_V1_INFO_PACKET",
    [PSN_V1_DATA_PACKET] = "PSN_V1_DATA_PACKET",
}

local PSN_INFO_PACKET_HEADER = 0x0000
local PSN_INFO_SYSTEM_NAME = 0x0001
local PSN_INFO_TRACKER_LIST = 0x0002

local INFO_CHUNK_IDS = {
    [PSN_INFO_PACKET_HEADER] = "PSN_INFO_PACKET_HEADER",
    [PSN_INFO_SYSTEM_NAME] = "PSN_INFO_SYSTEM_NAME",
    [PSN_INFO_TRACKER_LIST] = "PSN_INFO_TRACKER_LIST",
}

local PSN_DATA_PACKET_HEADER = 0x0000
local PSN_DATA_TRACKER_LIST = 0x0001

local DATA_CHUNK_IDS = {
    [PSN_DATA_PACKET_HEADER] = "PSN_DATA_PACKET_HEADER",
    [PSN_DATA_TRACKER_LIST] = "PSN_DATA_TRACKER_LIST",
}

local PSN_INFO_TRACKER_NAME = 0x0000
local TRACKER_LIST_CHUNK_IDS = {
    [PSN_INFO_TRACKER_NAME] = "PSN_INFO_TRACKER_NAME"
}

local PSN_DATA_TRACKER_POS = 0x0000
local PSN_DATA_TRACKER_SPEED = 0x0001
local PSN_DATA_TRACKER_ORI = 0x0002
local PSN_DATA_TRACKER_STATUS = 0x0003
local PSN_DATA_TRACKER_ACCEL = 0x0004
local PSN_DATA_TRACKER_TRGTPOS = 0x0005

local TRACKER_CHUNK_IDS = {
    [PSN_DATA_TRACKER_POS] = "PSN_DATA_TRACKER_POS",
    [PSN_DATA_TRACKER_SPEED] = "PSN_DATA_TRACKER_SPEED",
    [PSN_DATA_TRACKER_ORI] = "PSN_DATA_TRACKER_ORI",
    [PSN_DATA_TRACKER_STATUS] = "PSN_DATA_TRACKER_STATUS",
    [PSN_DATA_TRACKER_ACCEL] = "PSN_ DATA_TRACKER_ACCEL",
    [PSN_DATA_TRACKER_TRGTPOS] = "PSN_ DATA_TRACKER_TRGTPOS",
}

local pf_base_chunk_id = ProtoField.new("Chunk ID", "psn.chunk_id", ftypes.UINT16, BASE_CHUNK_IDS, base.HEX)
local pf_info_chunk_id = ProtoField.new("Chunk ID", "psn.info_chunk_id", ftypes.UINT16, INFO_CHUNK_IDS, base.HEX)
local pf_data_chunk_id = ProtoField.new("Chunk ID", "psn.data_chunk_id", ftypes.UINT16, DATA_CHUNK_IDS, base.HEX)
local pf_tracker_chunk_id = ProtoField.new("Chunk ID", "psn.tracker_chunk_id", ftypes.UINT16, TRACKER_CHUNK_IDS, base.HEX)
local pf_tracker_list_chunk_id = ProtoField.new("Chunk ID", "psn.tracker_list_chunk_id", ftypes.UINT16, TRACKER_LIST_CHUNK_IDS, base.HEX)

local pf_data_field = ProtoField.new("Data Field", "psn.data_field", ftypes.UINT16, nil, base.HEX)
local pf_data_len = ProtoField.new("Data Length", "psn.data_len", ftypes.UINT16, nil, base.DEC, 0x7fff)
local pf_sub_chunks = ProtoField.new("Has Sub Chunks", "psn.has_sub_chunks", ftypes.BOOLEAN, {"Yes", "No"}, 16, 0x8000)

local pf_children = ProtoField.new("Children", "snet.children", ftypes.NONE)

local pf_timestamp = ProtoField.new("Timestamp", "psn.timestamp", ftypes.UINT64, nil, base.DEC)
local pf_version_high = ProtoField.new("Version High", "psn.version_high", ftypes.UINT8, nil, base.DEC)
local pf_version_low = ProtoField.new("Version Low", "psn.version_low", ftypes.UINT8, nil, base.DEC)
local pf_frame_id = ProtoField.new("Frame ID", "psn.frame_id", ftypes.UINT8, nil, base.DEC)
local pf_frame_packet_count = ProtoField.new("Frame Packet Count", "psn.frame_packet_count", ftypes.UINT8, nil, base.DEC)

local pf_system_name = ProtoField.new("System Name", "psn.system_name", ftypes.STRING, nil)
local pf_tracker_id = ProtoField.new("Tracker ID", "psn.tracker_id", ftypes.UINT16, nil, base.DEC)
local pf_tracker_name = ProtoField.new("Tracker Name", "psn.tracker_name", ftypes.STRING, nil)

local pf_vector_x = ProtoField.new("X", "psn.vector_x", ftypes.FLOAT, nil)
local pf_vector_y = ProtoField.new("Y", "psn.vector_y", ftypes.FLOAT, nil)
local pf_vector_z = ProtoField.new("Z", "psn.vector_z", ftypes.FLOAT, nil)
local pf_validity = ProtoField.new("Validity", "psn.validity", ftypes.FLOAT, nil)

local pf_v1_header = ProtoField.new("Header", "snet.v1_header", ftypes.NONE)
local pf_v1_tracker = ProtoField.new("Tracker", "snet.v1_tracker", ftypes.NONE)
local pf_v1_position = ProtoField.new("Position", "snet.v1_position", ftypes.NONE)
local pf_v1_velocity = ProtoField.new("Velocity", "snet.v1_velocity", ftypes.NONE)
local pf_v1_packet_counter = ProtoField.new("Packet Counter", "psn.v1_packet_counter", ftypes.UINT32, nil, base.DEC)
local pf_v1_world_id = ProtoField.new("World ID", "psn.v1_world_id", ftypes.UINT16, nil, base.DEC)
local pf_v1_tracker_count = ProtoField.new("Tracker Count", "psn.v1_tracker_count", ftypes.UINT16, nil, base.DEC)
local pf_v1_frame_index = ProtoField.new("Frame Index", "psn.frame_index", ftypes.UINT8, nil, base.DEC)
local pf_v1_object_state = ProtoField.new("Object State", "psn.object_state", ftypes.UINT16, nil, base.DEC)
local pf_v1_info_xml = ProtoField.new("V1 Info XML", "psn.info_xml", ftypes.STRING, nil)

p_psn.fields = {pf_base_chunk_id, pf_info_chunk_id, pf_data_chunk_id, pf_tracker_chunk_id, pf_tracker_list_chunk_id,
                    pf_data_field, pf_data_len, pf_sub_chunks, pf_children,
                    pf_timestamp, pf_version_high, pf_version_low, pf_frame_id, pf_frame_packet_count,
                    pf_system_name, pf_tracker_id, pf_tracker_name,
                    pf_vector_x, pf_vector_y, pf_vector_z, pf_validity,
                    pf_v1_header, pf_v1_tracker, pf_v1_position, pf_v1_velocity,
                    pf_v1_packet_counter, pf_v1_world_id, pf_v1_tracker_count, pf_v1_frame_index, pf_v1_object_state, 
                    pf_v1_info_xml,
}

function dissect_chunk(buf, tree, id_field)
    local chunk_id = buf:range(0,2):le_uint()
    local data_field = buf:range(2,2):le_uint()
    local data_len = bit.band(data_field, 0x7fff)

    tree:add_le(id_field, buf:range(0,2))
    local data_field = tree:add_le(pf_data_field, buf:range(2,2))

    data_field:add_le(pf_data_len, buf:range(2,2))
    data_field:add_le(pf_sub_chunks, buf:range(2,2))

    local child_buf = buf:range(4, data_len)
    local child_tree = tree:add(pf_children, child_buf)

    local remaining = nil
    if 4 + data_len < buf:len() then
        remaining = buf:range(4 + data_len)
    end

    return chunk_id, child_buf, child_tree, remaining
end

function dissect_header(buf, tree)

    tree:add_le(pf_timestamp, buf:range(0,8))
    tree:add(pf_version_high, buf:range(8,1))
    tree:add(pf_version_low, buf:range(9,1))
    tree:add(pf_frame_id, buf:range(10,1))
    tree:add(pf_frame_packet_count, buf:range(11,1))

end

function dissect_system_name(buf, tree)

    tree:add(pf_system_name, buf)

end

function dissect_info_tracker_list(buf, tree)

    while buf do
        tracker_id, child_buf, child_tree, buf = dissect_chunk(buf, tree, pf_tracker_id)
        
        while child_buf do
            chunk_id, info_buf, info_tree, child_buf = dissect_chunk(child_buf, child_tree, pf_tracker_list_chunk_id)
            
            if chunk_id == PSN_INFO_TRACKER_NAME then
                info_tree:add(pf_tracker_name, info_buf)
            end
        end
    end
    
end

function dissect_data_tracker_list(buf, tree)

    while buf do
        tracker_id, child_buf, child_tree, buf = dissect_chunk(buf, tree, pf_tracker_id)
        
        while child_buf do
            chunk_id, info_buf, info_tree, child_buf = dissect_chunk(child_buf, child_tree, pf_tracker_chunk_id)
            
            if chunk_id == PSN_DATA_TRACKER_POS 
                    or chunk_id == PSN_DATA_TRACKER_SPEED 
                    or chunk_id == PSN_DATA_TRACKER_ORI
                    or chunk_id == PSN_DATA_TRACKER_ACCEL
                    or chunk_id == PSN_DATA_TRACKER_TRGTPOS
                    then
                info_tree:add_le(pf_vector_x, info_buf:range(0,4))
                info_tree:add_le(pf_vector_y, info_buf:range(4,4))
                info_tree:add_le(pf_vector_z, info_buf:range(8,4))
            else
                info_tree:add_le(pf_validity, info_buf:range(0,4))
            end
        end
    end
    
end

function dissect_info(buf, tree)

    while buf do
        chunk_id, child_buf, child_tree, buf = dissect_chunk(buf, tree, pf_info_chunk_id)
        
        if chunk_id == PSN_INFO_PACKET_HEADER then
            dissect_header(child_buf, child_tree)
        elseif chunk_id == PSN_INFO_SYSTEM_NAME then
            dissect_system_name(child_buf, child_tree)
        elseif chunk_id == PSN_INFO_TRACKER_LIST then
            dissect_info_tracker_list(child_buf, child_tree)
        end
    end
    
end

function dissect_data(buf, tree)
    
    while buf do
        chunk_id, child_buf, child_tree, buf = dissect_chunk(buf, tree, pf_data_chunk_id)
        
        if chunk_id == PSN_DATA_PACKET_HEADER then
            dissect_header(child_buf, child_tree)
        elseif chunk_id == PSN_DATA_TRACKER_LIST then
            dissect_data_tracker_list(child_buf, child_tree)
        end
    end
    
end

function dissect_v1_header(buf, tree)
    
    local header = tree:add(pf_v1_header, buf:range(0, 18))

    header:add_le(pf_base_chunk_id, buf:range(0,2))
    header:add_le(pf_v1_packet_counter, buf:range(2,4))
    header:add_le(pf_version_high, buf:range(6,1))
    header:add_le(pf_version_low, buf:range(7,1))
    header:add_le(pf_v1_world_id, buf:range(8,2))
    header:add_le(pf_v1_tracker_count, buf:range(10,2))
    header:add_le(pf_frame_id, buf:range(12,1))
    header:add_le(pf_frame_packet_count, buf:range(13,1))
    header:add_le(pf_v1_frame_index, buf:range(14,1))
    
    return buf:range(10,2):le_uint()
end

function dissect_v1_tracker(buf, tree)

    tree:add_le(pf_tracker_id, buf:range(0,2))
    tree:add_le(pf_v1_object_state, buf:range(2,2))
    
    local pos_tree = tree:add(pf_v1_position, buf:range(8,12))
    pos_tree:add_le(pf_vector_x, buf:range(8,4))
    pos_tree:add_le(pf_vector_y, buf:range(12,4))
    pos_tree:add_le(pf_vector_z, buf:range(16,4))

    local vel_tree = tree:add(pf_v1_velocity, buf:range(20,12))
    vel_tree:add_le(pf_vector_x, buf:range(20,4))
    vel_tree:add_le(pf_vector_y, buf:range(24,4))
    vel_tree:add_le(pf_vector_z, buf:range(28,4))
    
end

function dissect_v1_trackers(buf, tree, count)
    
    local index = 0

    for i = 1,count do
        local child_buf = buf:range(index, 32)
        local child = tree:add_le(pf_v1_tracker, child_buf)
        dissect_v1_tracker(child_buf, child)
        
        index = index + 32
    end

end
 
function dissect_base(buf, root)
    local psn_id = buf:range(0,2):le_uint()
  
    if psn_id == PSN_V1_DATA_PACKET then
        count = dissect_v1_header(buf, root)
      
        dissect_v1_trackers(buf:range(18), root, count)
        
    elseif psn_id == PSN_V1_INFO_PACKET then
        root:add(pf_v1_info_xml, buf:range())
    else
  
        chunk_id, child_buf, child_tree = dissect_chunk(buf, root, pf_base_chunk_id)
      
        if chunk_id == PSN_INFO_PACKET then
            dissect_info(child_buf, child_tree)
        elseif chunk_id == PSN_DATA_PACKET then
            dissect_data(child_buf, child_tree)
        end
  
    end

end
 

function p_psn.dissector (buf, pkt, root)
    -- validate packet length is adequate, otherwise quit
    if buf:len() == 0 then return end
    pkt.cols.protocol:set(p_psn.name)
 
    local tree = root:add(p_psn, buf:range(0,pktlen))
  
    dissect_base(buf, tree)

end
 
DissectorTable.get("udp.port"):add(56565, p_psn)

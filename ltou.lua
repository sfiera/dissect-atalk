--
-- LocalTalk over UDP Wireshark dissector
-- ©2023 Chris Pickel <sfiera@twotaled.com>
-- 
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--

-- Author’s note:
-- Some parts of this dissector duplicate the LLAP and DDP dissectors
-- which are built-in to Wireshark and implemented in packet-atalk.c.
-- However, I couldn’t find a way to delegate to those dissectors,
-- only to the inner ddp.type dissector table.

ltou_protocol  = Proto("LToU", "LocalTalk over UDP")
f_sender_id    = ProtoField.uint32("ltou.sender_id", "sender", base.DEC)
f_dst_node     = ProtoField.uint8("ltou.dst_node", "destination node", base.DEC)
f_src_node     = ProtoField.uint8("ltou.src_node", "source node", base.DEC)
f_llap_type    = ProtoField.uint8("ltou.llap_type", "LLAP type", base.DEC)
ltou_protocol.fields = {
    f_sender_id,
    f_dst_node,
    f_src_node,
    f_llap_type,
}

ddp_protocol   = Proto("LToU-DDP", "LToU Datagram Delivery Protocol")
f_size         = ProtoField.uint16("ltou.size", "size", base.DEC)
f_checksum     = ProtoField.uint16("ltou.checksum", "checksum", base.DEC)
f_dst_network  = ProtoField.uint16("ltou.dst_network", "destination network", base.DEC)
f_src_network  = ProtoField.uint16("ltou.src_network", "source network", base.DEC)
f_dst_node     = ProtoField.uint8("ltou.dst_node", "destination node", base.DEC)
f_src_node     = ProtoField.uint8("ltou.src_node", "source node", base.DEC)
f_dst_socket   = ProtoField.uint8("ltou.dst_socket", "destination socket", base.DEC)
f_src_socket   = ProtoField.uint8("ltou.src_socket", "source socket", base.DEC)
f_ddp_type     = ProtoField.uint8("ltou.ddp_type", "DDP type", base.DEC)
ddp_protocol.fields = {
    f_size,
    f_checksum,
    f_dst_network,
    f_src_network,
    f_dst_node,
    f_src_node,
    f_dst_socket,
    f_src_socket,
    f_ddp_type,
}

local ddp = DissectorTable.get("ddp.type")

function ltou_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 7 then
        return
    end
    pinfo.cols.protocol = ltou_protocol.name

    local subtree = tree:add(ltou_protocol, buffer(), "LocalTalk over UDP")
    subtree:add_le(f_sender_id, buffer(0,4))
    subtree:add_le(f_dst_node, buffer(4,1))
    subtree:add_le(f_src_node, buffer(5,1))

    local llap_type = buffer(6,1):uint()
    if llap_type == 0x01 then
        subtree:add_le(f_llap_type, buffer(6,1)):append_text(" (DDP)")
        dissect_ddp(buffer(7):tvb(), pinfo, tree)
    elseif llap_type == 0x02 then
        subtree:add_le(f_llap_type, buffer(6,1)):append_text(" (ExtDDP)")
        dissect_ext_ddp(buffer(7):tvb(), pinfo, tree)
    elseif llap_type == 0x81 then
        subtree:add_le(f_llap_type, buffer(6,1)):append_text(" (Enq)")
        pinfo.cols.info = "LLAP Enq: " .. buffer(5,1):uint() .. " → " .. buffer(4,1):uint()
    elseif llap_type == 0x82 then
        subtree:add_le(f_llap_type, buffer(6,1)):append_text(" (Ack)")
        pinfo.cols.info = "LLAP Ack: " .. buffer(5,1):uint() .. " → " .. buffer(4,1):uint()
    else
        subtree:add_le(f_llap_type, buffer(6,1)):append_text(" (Unknown)")
    end
end

function dissect_ddp(buffer, pinfo, tree)
    if buffer:len() < 5 then
        return
    end
    local subtree = tree:add(ddp_protocol, buffer(), "Datagram Delivery Protocol")

    subtree:add(f_dst_socket, buffer(2,1))
    subtree:add(f_src_socket, buffer(3,1))
    subtree:add(f_size, buffer(0,2))

    ddp_type = buffer(4,1):uint()
    subtree:add(f_ddp_type, buffer(4,1)):append_text(" (" .. ddp_type_str(ddp_type) .. ")")

    size = buffer(0,2):uint()
    ddp:try(ddp_type, buffer(5, size - 5):tvb(), pinfo, tree)
end

function dissect_ext_ddp(buffer, pinfo, tree)
    if buffer:len() < 13 then
        return
    end
    local subtree = tree:add(ddp_protocol, buffer(), "Datagram Delivery Protocol (Extended)")

    subtree:add(f_dst_network, buffer(4,2))
    subtree:add(f_dst_node, buffer(8,1))
    subtree:add(f_dst_socket, buffer(10,1))
    subtree:add(f_src_network, buffer(6,2))
    subtree:add(f_src_node, buffer(9,1))
    subtree:add(f_src_socket, buffer(11,1))
    subtree:add(f_size, buffer(0,2))
    subtree:add(f_checksum, buffer(2,2))

    ddp_type = buffer(12,1):uint()
    subtree:add(f_ddp_type, buffer(12,1)):append_text(" (" .. ddp_type_str(ddp_type) .. ")")

    size = buffer(0,2):uint()
    ddp:try(ddp_type, buffer(13, size - 13):tvb(), pinfo, tree)
end

function ddp_type_str(t)
    if t == 0x01 then return "RTMP-DATA"
    elseif t == 0x02 then return "NBP"
    elseif t == 0x03 then return "ATP"
    elseif t == 0x04 then return "AEP"
    elseif t == 0x05 then return "RTMP-REQ"
    elseif t == 0x06 then return "ZIP"
    elseif t == 0x07 then return "ADSP"
    elseif t == 0x58 then return "EIGRP"
    else return "Unknown"
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1954, ltou_protocol)

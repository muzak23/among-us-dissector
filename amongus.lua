amongus_protocol = Proto("amongus",  "Among Us Protocol")


--------------------------------------------------
--
-- Packet analysis tables 
--
--------------------------------------------------

packet_type = {
	NORMAL 		= 0,
	RELIABLE 	= 1,
	HELLO 		= 8,
	DISCONNECT 	= 9,
	ACK 		= 10,
	FRAGMENT 	= 11,
	PING 		= 12
}

-- packet_type = NORMAL


-- packet_type = RELIABLE

root_message_type = {
	HostGame        = 0,
	JoinGame        = 1,
	StartGame       = 2,
	RemoveGame      = 3,
	RemovePlayer    = 4,
	GameData        = 5,
	GameDataTo      = 6,
	JoinedGame      = 7,
	EndGame         = 8,
	GetGameList     = 9,
	AlterGame       = 10,
	KickPlayer      = 11,
	WaitForHost     = 12,
	Redirect        = 13,
	ReselectServer  = 14,
	GetGameListV2   = 16,  -- intentional jump in value
	ReportPlayer    = 17
}

gameData_type = {
	Data 			= 1,
	RPC 			= 2,
	Spawn 			= 4,
	Despawn 		= 5,
	SceneChange 	= 6,
	Ready 			= 7,
	ChangeSettings 	= 8,
	ClientInfo 		= 205
}

RPC_type = {
	PlayAnimation     = 0,
	CompleteTask      = 1,
	SyncSettings      = 2,
	SetInfected       = 3,
	Exiled            = 4,
	CheckName         = 5,
	SetName           = 6,
	CheckColor        = 7,
	SetColor          = 8,
	SetHat            = 9,
	SetSkin           = 10,
	ReportDeadBody    = 11,
	MurderPlayer      = 12,
	SendChat          = 13,
	StartMeeting      = 14,
	SetScanner        = 15,
	SendChatNote      = 16,
	SetPet            = 17,
	SetStartCounter   = 18,
	EnterVent         = 19,
	ExitVent          = 20,
	SnapTo            = 21,
	Close             = 22,
	VotingComplete    = 23,
	CastVote          = 24,
	ClearVote         = 25,
	AddVote           = 26,
	CloseDoorsOfType  = 27,
	RepairSystem      = 28,
	SetTasks          = 29,
	ClimbLadder       = 30,
	UsePlatform       = 31
}
	








--------------------------------------------------
--
-- Register the fields 
--
--------------------------------------------------

packet_type_field		= ProtoField.int32("amongus.packet_type"		, "packetType"		, base.DEC)
message_length_field	= ProtoField.int32("amongus.message_length"		, "messageLength"	, base.DEC)
nonce_field 			= ProtoField.int16("amongus.nonce"				, "nonce"			, base.DEC)
root_message_type_field	= ProtoField.int32("amongus.root_message_type"	, "rootMessageType"	, base.DEC)
gameID_field			= ProtoField.int32("amongus.gameID" 			, "gameID"			, base.DEC)
senderID_field			= ProtoField.int32("amongus.senderID"			, "senderID"		, base.DEC)
gameData_type_field 	= ProtoField.int32("amongus.gameData_type"		, "gameData"		, base.DEC)
RPC_type_field			= ProtoField.bytes("amongus.rpc_type"			, "RPCtype")

ack_packets_field 		= ProtoField.bytes("amongus.ack_packets" 		, "acknowledgedPackets")

amongus_protocol.fields = { packet_type_field, message_length_field, 
							nonce_field, root_message_type_field, 
							gameID_field, senderID_field,
							gameData_type_field, RPC_type_field,
							ack_packets_field }



--------------------------------------------------
--
-- Main function for dissector logic 
--
--------------------------------------------------

function amongus_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	print("full length: " .. length)
	if length == 0 then return end

	pinfo.cols.protocol = amongus_protocol.name

	local subtree = tree:add(amongus_protocol, buffer(), "Among Us Protocol Data")

	print("buffer(0,0): " .. buffer(0,1))

	local packet_type_value = buffer(0,1):int()
	subtree:add(packet_type_field,	buffer(0,1)):append_text(" (" .. name(packet_type, packet_type_value) ..")")


	-- If Packet Type: 	NORMAL


	-- If Packet Type: 	RELIABLE  (TODO: MAY HAVE MORE THAN ONE MESSAGE PER PACKET)
	if packet_type_value == packet_type['RELIABLE'] then
		local nonce_value = buffer(1,2):int() -- TODO: fix/confirm bytes, since WS is currently bugged -- ID of the packet so it can be ACK'd
		subtree:add(nonce_field, buffer(1,2))
		
		local root_message_type_value = buffer(5,1):int()
		subtree:add(root_message_type_field, buffer(5,1)):append_text(" (" .. name(root_message_type, root_message_type_value) .. ")")
	

		-- If Root Message Type: GameData   TODO: these can also have more than one message
		if root_message_type_value == root_message_type['GameData'] then
			local gameID_value = buffer(6,1):int() -- TODO: confirm bytes, and decode the game code
			subtree:add(gameID_field, buffer(6,1)):append_text(" (Not yet implemented.)")
		
			local gameData_type_value = buffer(12,1):int()
			subtree:add(gameData_type_field, buffer(12,1)):append_text(" (" .. name(gameData_type, gameData_type_value) .. ")")
			
			
			-- If GameData type is RPC
			if gameData_type == gameData_type['RPC'] then
				local senderID_value = buffer(14,1):int()
				subtree:add(senderID, buffer(14,1))
			
				local RPC_type_value = buffer(14,1):int()
				subtree:add(RPC_type_field, buffer(14,1)):append_text(" (" .. name(RPC_type, RPC_type_value) .. ")")
				
			
			end
		
		end
		
	
	-- If Packet Type: HELLO
	
		--elseif packet_type_value == packet_type['HELLO']


	-- If Packet type: DISCONNECT


	-- If Packet type: ACK
	elseif packet_type_value == packet_type['ACK'] then
		local nonce_value = buffer(1,2):int()
		subtree:add(nonce_field, buffer(1,2))
		
		local ack_packets_value = buffer(3,1):int()
		subtree:add(ack_packets_field, buffer(3,1))
		
		
	-- If Packet type: FRAGMENT
	
	end  -- if packet_type
end -- main function



--------------------------------------------------
--
-- Helper functions 
--
--------------------------------------------------

-- Helper function to get the name of a key from a value 
-- Ex. 	packet_type['RELIABLE']	== 1
-- 		name(packet_type, 1) 	== 'RELIABLE'

function name(table, value)
  for k,v in pairs(table) do
    if v==value then return k end
  end
  return "Unknown"
end



--------------------------------------------------
--
-- Register ports 
--
--------------------------------------------------

local udp_port = DissectorTable.get("udp.port")
udp_port:add(22023, amongus_protocol)  -- main port used, but others are possible
udp_port:add(22123, amongus_protocol)
udp_port:add(22223, amongus_protocol)
udp_port:add(22323, amongus_protocol)
udp_port:add(22423, amongus_protocol)
udp_port:add(22523, amongus_protocol)
udp_port:add(22623, amongus_protocol)
udp_port:add(22723, amongus_protocol)
udp_port:add(22823, amongus_protocol)
udp_port:add(22923, amongus_protocol)


-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(22023, amongus_protocol)

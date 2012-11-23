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


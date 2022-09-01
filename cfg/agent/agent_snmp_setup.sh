# stop snmp proccess
sudo systemctl stop snmpd

# enable snmp proccess at system startup
sudo systemctl enable snmpd

# backup the default configuration file
sudo mv /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.bak

# copy new config to the snmpconfpath directory
sudo cp snmpd.conf /etc/snmp/

# start snmp proccess
sudo systemctl start snmpd

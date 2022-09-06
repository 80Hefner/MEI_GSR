# stop snmp proccess
sudo systemctl stop snmpd

# enable snmp proccess at system startup
sudo systemctl enable snmpd

# copy new config to the snmpconfpath directory
sudo cp snmpd.conf /etc/snmp/

# start snmp proccess
sudo systemctl start snmpd

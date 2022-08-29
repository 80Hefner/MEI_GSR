
# stop the agent
#sudo systemctl stop snmpd
service snmpd stop

# backup the default configuration file
sudo mv /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.bak

# copy the files to the snmpconfpath directory
sudo cp snmpd.conf /etc/snmp/
sudo cp snmp.conf /etc/snmp/

# copy mib file to mibs directory
sudo cp PROXY-SEC-MIB.txt /usr/share/snmp/mibs/

# start the agent
#sudo systemctl start snmpd
service snmpd start

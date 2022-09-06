# stop snmp proccess
sudo systemctl stop snmpd

# enable snmp proccess at system startup
sudo systemctl enable snmpd

# copy the files to the snmpconfpath directory
# sudo cp snmpd.conf /etc/snmp/
# sudo cp snmp.conf /etc/snmp/

# copy mib file to mibs directory
sudo cp GSR2122-SEC-MIB.txt /usr/share/snmp/mibs/

# start snmp proccess
sudo systemctl start snmpd

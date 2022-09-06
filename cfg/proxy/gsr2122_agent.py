#!/usr/bin/env python
#
# python-netsnmpagent simple example agent
#
# Copyright (c) 2013-2019 Pieter Hollants <pieter@hollants.com>
# Licensed under the GNU Lesser Public License (LGPL) version 3
#

#
# This is an example of a simple SNMP sub-agent using the AgentX protocol
# to connect to a master agent (snmpd), extending its MIB with the
# information from the included SIMPLE-MIB.txt.
#
# Use the included script run_simple_agent.sh to test this example.
#
# Alternatively, if you want to test with your system-wide snmpd instance,
# it must have as minimal configuration:
#
#   rocommunity <rosecret> 127.0.0.1
#   master agentx
#
# snmpd must be started first, then this agent must be started as root
# (because of the AgentX socket under /var/run/agentx/master), eg. via "sudo".
#
# Then, from a separate console and from inside the python-netsnmpagent
# directory, you can run eg.:
#
#  snmpwalk -v 2c -c <rosecret> -M+. localhost SIMPLE-MIB::simpleMIB
#
# If you wish to test setting values as well, your snmpd.conf needs a
# line like this:
#
#   rwcommunity <rwsecret> 127.0.0.1
#
# Then you can try something like:
#
#   snmpset -v 2c -c <rwsecret> -M+. localhost \
#     SIMPLE-MIB::simpleInteger i 0
#

import sys, os, signal
import optparse
import pprint

# Make sure we use the local copy, not a system-wide one
sys.path.insert(0, os.path.dirname(os.getcwd()))
import netsnmpagent

prgname = sys.argv[0]

# Process command line arguments
parser = optparse.OptionParser()
parser.add_option(
	"-m",
	"--mastersocket",
	dest="mastersocket",
	help="Sets the transport specification for the master agent's AgentX socket",
	default="/var/run/agentx/master"
)
parser.add_option(
	"-p",
	"--persistencedir",
	dest="persistencedir",
	help="Sets the path to the persistence directory",
	default="/var/lib/net-snmp"
)
(options, args) = parser.parse_args()

# Get terminal width for usage with pprint
rows, columns = os.popen("stty size", "r").read().split()

# First, create an instance of the netsnmpAgent class. We specify the
# fully-qualified path to SIMPLE-MIB.txt ourselves here, so that you
# don't have to copy the MIB to /usr/share/snmp/mibs.
try:
	agent = netsnmpagent.netsnmpAgent(
		AgentName      = "GSR2122Agent",
		MasterSocket   = options.mastersocket,
		PersistenceDir = options.persistencedir,
		MIBFiles       = []
	)
except netsnmpagent.netsnmpAgentException as e:
	print("{0}: {1}".format(prgname, e))
	sys.exit(1)

# Create the operations table
operationsTable = agent.Table(
	oidstr  = "GSR2122-SEC-MIB::operationsTable",
	indexes = [
		agent.Unsigned32()                  # idOper
	],
	columns = [
		# Columns begin with an index of 2 here because 1 is actually
		# used for the single index column above.
		# We must explicitly specify that the columns should be SNMPSETable.
		(2, agent.Integer32(), False),        # typeOper
        (3, agent.OctetString(), False),      # idSrc
		(4, agent.OctetString(), False),      # idDest
		(5, agent.OctetString(), False),      # oidArg
		(6, agent.OctetString(''), True),     # valueArg
		(7, agent.Integer32(0), True),        # typeArg
		(8, agent.Unsigned32(0), True),       # sizeArg
	],
	# Allow adding new records
	extendable = True
)

# Add the first operations table row
operationsTableRow1 = operationsTable.addRow([agent.Unsigned32(1)])
operationsTableRow1.setRowCell(2, agent.Integer32(2))
operationsTableRow1.setRowCell(3, agent.OctetString("10.0.1.21"))
operationsTableRow1.setRowCell(4, agent.OctetString("10.0.0.21"))
operationsTableRow1.setRowCell(5, agent.OctetString("1.3.6.1.1.1.1.5.0"))

# Create the agents table
agentsTable = agent.Table(
	oidstr  = "GSR2122-SEC-MIB::agentsTable",
	indexes = [
		agent.OctetString()                 # agentAlias
	],
	columns = [
		(2, agent.OctetString(), True),     # agentAddress
		(3, agent.OctetString(), False)     # agentCS
	],
	# Allow adding new records
	extendable = True
)

# Add the first agents table row
agentsTableRow1 = agentsTable.addRow([agent.OctetString("agent_alias")])
agentsTableRow1.setRowCell(2, agent.OctetString("10.0.0.21"))
agentsTableRow1.setRowCell(3, agent.OctetString("agent"))

# Create the managers table
managersTable = agent.Table(
	oidstr  = "GSR2122-SEC-MIB::managersTable",
	indexes = [
		agent.OctetString()                 # managerAlias
	],
	columns = [
		(2, agent.OctetString(), True),     # managerAddress
		(3, agent.OctetString(), False)     # managerCS
	],
	# Allow adding new records
	extendable = True
)

# Add the first managers table row
managersTableRow1 = managersTable.addRow([agent.OctetString("manager_alias")])
managersTableRow1.setRowCell(2, agent.OctetString("10.0.1.21"))
managersTableRow1.setRowCell(3, agent.OctetString("manager"))


# Finally, we tell the agent to "start". This actually connects the
# agent to the master agent.
try:
	agent.start()
except netsnmpagent.netsnmpAgentException as e:
	print("{0}: {1}".format(prgname, e))
	sys.exit(1)

print("{0}: AgentX connection to snmpd established.".format(prgname))

# Helper function that dumps the state of all registered SNMP variables
def DumpRegistered():
	for context in agent.getContexts():
		print("{0}: Registered SNMP objects in Context \"{1}\": ".format(prgname, context))
		vars = agent.getRegistered(context)
		pprint.pprint(vars, width=columns)
		print
DumpRegistered()

# Install a signal handler that terminates our simple agent when
# CTRL-C is pressed or a KILL signal is received
def TermHandler(signum, frame):
	global loop
	loop = False
signal.signal(signal.SIGINT, TermHandler)
signal.signal(signal.SIGTERM, TermHandler)

# Install a signal handler that dumps the state of all registered values
# when SIGHUP is received
def HupHandler(signum, frame):
	DumpRegistered()
signal.signal(signal.SIGHUP, HupHandler)

# The simple agent's main loop. We loop endlessly until our signal
# handler above changes the "loop" variable.
print("{0}: Serving SNMP requests, send SIGHUP to dump SNMP object state, press ^C to terminate...".format(prgname))

loop = True
while (loop):
	# Block and process SNMP requests, if available
	agent.check_and_process()

print("{0}: Terminating.".format(prgname))
agent.shutdown()

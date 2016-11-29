#!/usr/bin/python
import os
import json
import sys
import binascii
import struct
from datetime import datetime
from pymongo import MongoClient
from dateutil import parser

ROOT_TAG_IDX = 2

# Tag classes 
CLASS_MASK  = 0xC0
UNIVERSAL   = 0x00
APPLICATION = 0x40
CONTEXT     = 0x80
PRIVATE     = 0xC0

#Encoding type

FORM_MASK   = 0x20
PRIMITIVE   = 0x00
CONSTRUCTED = 0x20

#Length encoding
LEN_XTND    = 0x80
LEN_MASK    = 0x7F

#Tags
TAG_MASK    = 0x1F
ETAG_MASK   = 0x80
FTAG_MASK   = 0x7F
SEQUENCE    = 0x10
ENUMERATED  = 0x0A

def subscriptionIDType(val):
	val = decodeInteger(val)
	return {
		0: '"eND-USER-E164"',
		1: '"eND-USER-IMSI"',
		2: '"eND-USER-SIP-URI"',
		3: '"eND-USER-NAI"',
		4: '"eND-USER-PRIVATE"'
	}.get(val, None)

def servingNodeType(val):
	val = decodeInteger(val)
	return {
		0: '"sGSN"',
		1: '"pMIPSGW"',
		2: '"gTPSGW"',
		3: '"ePDG"',
		4: '"hSGW"',
		5: '"mME"'
	}.get(val, None)

def causeForRecClosing(val):
	val = decodeInteger(val)
	return {
		0: '"normalRelease"',
		4: '"abnormalRelease"',
		5: '"cAMELInitCallRelease"',
		16: '"volumeLimit"',
		17: '"timeLimit"',
		18: '"servingNodeChange"',
		19: '"maxChangeCond"',
		20: '"managementIntervention"',
		21: '"intraSGSNIntersystemChange"',
		22: '"rATChange"',
		23: '"mSTimeZoneChange"',
		24: '"sGSNPLMNIDChange"',
		52: '"unauthorizedRequestingNetwork"',
		53: '"unauthorizedLCSClient"',
		54: '"positionMethodFailure"',
		58: '"unknownOrUnreachableLCSClient"',
		59: '"listofDownstreamNodeChange"'
	}.get(val, None)

def apnSelectionMode(val):
	val = decodeInteger(val)
	return {
		0: '"mSorNetworkProvidedSubscriptionVerified"',
		1: '"mSProvidedSubscriptionNotVerified"',
		2: '"networkProvidedSubscriptionNotVerified"'
	}.get(val, None)

def chChSelectionMode(val):
	val = decodeInteger(val)
	return {
		0: '"servingNodeSupplied"',
		1: '"subscriptionSpecific"',
		2: '"aPNSpecific"',
		3: '"homeDefault"',
		4: '"roamingDefault"',
		5: '"visitingDefault"'
	}.get(val, None)

def rATType(val):
	val = decodeInteger(val)
	return {
		0: '"reserved"',
		1: '"utran"',
		2: '"geran"',
		3: '"wlan"',
		4: '"gan"',
		5: '"hspa-evolution"',
		6: '"eutran"'
	}.get(val, None)

def nodeName(path):
	return {
		(79, 0): "recordType",
		(79, 3): "servedIMSI",
		(79, 4): "p-GWAddress",
		(79, 4, 0): "iPBinV4Address",
		(79, 4, 1): "iPBinV6Address",
		(79, 4, 2): "iPTextV4Address",
		(79, 4, 3): "iPTextV6Address",
		(79, 5): "chargingID",
		(79, 6): "servingNodeAddress",
		(79, 6, 0): "iPBinV4Address",
		(79, 6, 1): "iPBinV6Address",
		(79, 6, 2): "iPTextV4Address",
		(79, 6, 3): "iPTextV6Address",
		(79, 7): "accessPointNameNI",
		(79, 8): "pdpPDNType",
		(79, 9): "servedPDPPDNAddress",
		(79, 9, 0): "iPAddress",
		(79, 9, 0, 0): "iPBinV4Address",
		(79, 9, 0, 1): "iPBinV6Address",
		(79, 9, 0, 2): "iPTextV4Address",
		(79, 9, 0, 3): "iPTextV6Address",
		(79, 11): "dynamicAddressFlag",
		(79, 13): "recordOpeningTime",
		(79, 14): "callDuration",
		(79, 15): "causeForRecClosing",
		(79, 16): "diagnostics",
		(79, 16, 0): "gsm0408Cause",
		(79, 16, 1): "gsm0902MapErrorValue",
		(79, 16, 2): "itu-tQ767Cause",
		(79, 16, 3): "networkSpecificCause",
		(79, 16, 4): "manufacturerSpecificCause",
		(79, 16, 5): "positionMethodFailureCause",
		(79, 16, 6): "unauthorizedLCSClientCause",
		(79, 17): "recordSequenceNumber",
		(79, 18): "nodeID",
		(79, 19): "recordExtensions",
		(79, 20): "localSequenceNumber",
		(79, 21): "apnSelectionMode",
		(79, 22): "servedMSISDN",
		(79, 23): "chargingCharacteristics",
		(79, 24): "chChSelectionMode",
		(79, 25): "iMSsignalingContext",
		(79, 27): "servingNodePLMNIdentifier",
		(79, 28): "pSFurnishChargingInformation",
		(79, 29): "servedIMEISV",
		(79, 30): "rATType",
		(79, 31): "mSTimeZone",
		(79, 32): "userLocationInformation",
		(79, 33): "cAMELChargingInformation",
		(79, 34): "listOfServiceData",
		(79, 34, 16): "sequence",
		(79, 34, 16, 1): "ratingGroup",
		(79, 34, 16, 2): "chargingRuleBaseName",
		(79, 34, 16, 3): "resultCode",
		(79, 34, 16, 4): "localSequenceNumber",
		(79, 34, 16, 5): "timeOfFirstUsage",
		(79, 34, 16, 6): "timeOfLastUsage",
		(79, 34, 16, 7): "timeUsage",
		(79, 34, 16, 8): "serviceConditionChange",
		(79, 34, 16, 9): "qoSInformationNeg",
		(79, 34, 16, 9, 1): "qCI",
		(79, 34, 16, 9, 2): "maxRequestedBandwithUL",
		(79, 34, 16, 9, 3): "maxRequestedBandwithDL",
		(79, 34, 16, 9, 4): "guaranteedBitrateUL",
		(79, 34, 16, 9, 5): "guaranteedBitrateDL",
		(79, 34, 16, 9, 6): "aRP",
		(79, 34, 16, 9, 7): "aPNAggregateMaxBitrateUL",
		(79, 34, 16, 9, 8): "aPNAggregateMaxBitrateDL",
		(79, 34, 16, 10): "servingNodeAddress",
		(79, 34, 16, 10, 0): "iPBinV4Address",
		(79, 34, 16, 10, 1): "iPBinV6Address",
		(79, 34, 16, 10, 2): "iPTextV4Address",
		(79, 34, 16, 10, 3): "iPTextV6Address",
		(79, 34, 16, 12): "datavolumeFBCUplink",
		(79, 34, 16, 13): "datavolumeFBCDownlink",
		(79, 34, 16, 14): "timeOfReport",
		(79, 34, 16, 16): "failureHandlingContinue",
		(79, 34, 16, 17): "serviceIdentifier",
		(79, 34, 16, 18): "pSFurnishChargingInformation",
		(79, 34, 16, 19): "aFRecordInformation",
		(79, 34, 16, 20): "userLocationInformation",
		(79, 34, 16, 21): "eventBasedChargingInformation",
		(79, 34, 16, 22): "timeQuotaMechanism",
		(79, 34, 16, 23): "serviceSpecificInfo",
		(79, 34, 16, 24): "threeGPP2UserLocationInformation",
		(79, 35): "servingNodeType",
		(79, 35, 10): "servingNodeType-e",
		(79, 36): "servedMNNAI",
		(79, 36, 0): "subscriptionIDType",
		(79, 36, 1): "subscriptionIDData",
		(79, 37): "p-GWPLMNIdentifier",
		(79, 38): "startTime",
		(79, 39): "stopTime",
		(79, 40): "served3gpp2MEID",
		(79, 41): "pDNConnectionChargingID",		
		(79, 42): "iMSIunauthenticatedFlag",
		(79, 43): "userCSGInformation",
		(79, 44): "threeGPP2UserLocationInformation",
		(79, 45): "servedPDPPDNAddressExt",
		(79, 46): "lowPriorityIndicator",
		(79, 47): "dynamicAddressFlagExt",
		(79, 49): "servingNodeiPv6Address"
	}.get(path, None)

def decodeInteger(val):
	i = 0
	for char in val:
		i <<= 8
		i |= ord(char)
	return i

def decodeBCD(val):
	i =""
	for byte in val:
		i += str(ord(byte)>>4)
		i += str(ord(byte)&0x0F)
	return i

def decodeTimeStamp(val):
	#dt_string = "20%s%s%s" % (decodeBCD(val[:6]), str(val[6:7]), decodeBCD(val[7:]))
	#print dt_string
	#print datetime.datetime(dt_string)
	#return "%s" % datetime.strptime(dt_string[:12], "%y%m%d%H%M%S")
	#return parser.parse(dt_string, yearfirst=True)
	#return '"%s"' % datetime.strptime(dt_string, "%y%m%d%H%M%S%z")
	return '"20%s%s%s"' % (decodeBCD(val[:6]), str(val[6:7]), decodeBCD(val[7:]))

def decodeTBCD(val):
	#1611171614282b0300
	#16-11-17 16:14:28 2b 0300
	i = ""
	for bit8 in val:
		h_bit4 = ord(bit8)&0x0F
		l_bit4 = ord(bit8)>>4
		i += str(h_bit4)
		if l_bit4 != 0x0F:
			i += str(l_bit4)
	return i

def decodeIMSI(val):
	#1611171614282b0300
	#16-11-17 16:14:28 2b 0300
	i = ""
	for bit8 in val:
		h_bit4 = ord(bit8)&0x0F
		l_bit4 = ord(bit8)>>4
		i += str(h_bit4)
		if l_bit4 != 0x0F:
			i += str(l_bit4)
	return '"%s"' % i

def decodeIpV4BinToString(val):
	#50 4b 8c  f8
	#80 75 140 248
	return '"%d.%d.%d.%d"' % (ord(val[0]), ord(val[1]), ord(val[2]), ord(val[3]))

def decodeIA5String(val):
	return '"%s"' % str(val)

def decodeBoolean(val):
	if val:
		return "true"
	else:
		return "false"

def decodePdpPDNType(val):
	#f101
	i = ""
	if ord(val[0])&0x0F == 0:
		i += '{"ETSI": '
	elif ord(val[0])&0x0F == 1:
		i += '{"IETF": '
	else:
		i += '{"UNKNOWN": '
	if ord(val[1]) == 1:
		i += '"PPP"}'
	else:
		i += '"UNKNOWN"}'
	return i

def leaveAsIs(val):
	return '"%s"' % str(binascii.hexlify(val))

def decodeULI(val):
	if ord(val[0]) == 0:
		return '{"GLT": "%s", "PLMN": "%s", "LAC": %s, "CI": %s}' % ("CGI", decodeTBCD(val[1:4]), decodeInteger(val[4:6]), decodeInteger(val[6:8]))
	elif ord(val[0]) == 1:
		return '{"GLT": "%s", "PLMN": "%s", "LAC": %s, "SAC": %s}' % ("SAI", decodeTBCD(val[1:4]), decodeInteger(val[4:6]), decodeInteger(val[6:8]))
	elif ord(val[0]) == 2: 
		return '{"GLT": "%s", "PLMN": "%s", "LAC": %s, "RAC": %s}' % ("RAI", decodeTBCD(val[1:4]), decodeInteger(val[4:6]), decodeInteger(val[6:8]))
	else:
		return '{"GLT": "%s", "PLMN": "%s", "ERR": %s, "ERR": %s}' % (ord(val[0]), decodeTBCD(val[1:4]), decodeInteger(val[4:6]), decodeInteger(val[6:8]))

def decodeTimeZone(val):
	daylight = (ord(val[1:])%0x3)
	if (ord(val[1:])%0x4):
		sign = '-'
	else: 
		sign = '+'
	shift = int(decodeTBCD(val[:1]))
	minutes = (shift * 15) + (daylight * 60)
	time = '{:02d}:{:02d}'.format(*divmod(minutes, 60))
	return '"%s%s"' % (sign, time)

def serviceConditionChange(bitstr):
	conditionStr = ""
	condition = {
		2**0: "userLocationChange",
		2**1: "tAIChange",
		2**2: "eCGIChange",
		2**3: "envelopeClosure",
		2**4: "serviceSpecificUnitLimit",
		2**5: "volumeLimit",
		2**6: "timeLimit",
		2**7: "recordClosure",
		2**8: "dCCAServiceSpecificUnitExhausted",
		2**9: "rAIChange",
		2**10: "cGI-SAIChange",
		2**11: "dCCATerminateOngoingSession",
		2**12: "dCCARetryAndTerminateOngoingSession",
		2**13: "dCCAContinueOngoingSession",
		2**14: "dCCAReauthorisationRequest",
		2**15: "reserved1",
		2**16: "dCCAValidityTimeout",
		2**17: "dCCAVolumeExhausted",
		2**18: "dCCATimeExhausted",
		2**19: "dCCAServiceSpecificUnitThresholdReached",
		2**20: "dCCAVolumeThresholdReached",
		2**21: "dCCATimeThresholdReached",
		2**22: "serviceStop",
		2**23: "configurationChange",
		2**24: "reserved",
		2**25: "serviceIdledOut",
		2**26: "rATChange",
		2**27: "pDPContextRelease",
		2**28: "tariffTimeSwitch",
		2**29: "sGSNPLMNIDChange",
		2**30: "sGSNChange",
		2**31: "qoSChange"
	}

	for i in reversed(range(0, 33)):
		#if i == 0:
		#	x = decodeInteger(bitstr)&0	
		#else:
		x = decodeInteger(bitstr)&(2**i)
		if x:
			conditionStr += ',"%s"' % condition.get(x, "NaN")
			#conditionStr += ',' + '"' + condition.get(x, "NaN") + '"'
	#for i in condition:
		#decodeInteger(bitstr)&condition.get(i)
	return "[%s]" % conditionStr[1:]

#dCCATimeThresholdReached
#volumeLimit
#userLocationChange


#52f010
#250f01

#0152f01000ea2a82
#10250f0100aea228


funcDict = {
	'recordType': decodeInteger,
	'chargingID': decodeInteger,
	'servedIMSI': decodeIMSI,
	'iPBinV4Address': decodeIpV4BinToString,
	'accessPointNameNI': decodeIA5String,
	'pdpPDNType': decodePdpPDNType,
	'dynamicAddressFlag': decodeBoolean,
	'recordOpeningTime': decodeTimeStamp,
	'callDuration': decodeInteger,
	'causeForRecClosing': causeForRecClosing,
	'recordSequenceNumber': decodeInteger,
	'nodeID': decodeIA5String,
	'localSequenceNumber': decodeInteger,
	'apnSelectionMode': apnSelectionMode,
	'servedMSISDN': decodeIMSI,
	'chargingCharacteristics': leaveAsIs,
	'chChSelectionMode': chChSelectionMode,
	'servingNodePLMNIdentifier': decodeIMSI,
	'servedIMEISV': decodeIMSI,
	'rATType': rATType,
	'userLocationInformation': decodeULI,
	'mSTimeZone': decodeTimeZone,
	'ratingGroup': decodeInteger,
	'chargingRuleBaseName': decodeIA5String,
	'localSequenceNumber': decodeInteger,
	'timeOfFirstUsage': decodeTimeStamp,
	'timeOfLastUsage': decodeTimeStamp,
	'timeUsage': decodeInteger,
	'serviceConditionChange': serviceConditionChange,
	'timeOfReport': decodeTimeStamp,
	'datavolumeFBCUplink': decodeInteger,
	'datavolumeFBCDownlink': decodeInteger,
	'servingNodeType-e': servingNodeType,
	'subscriptionIDType': subscriptionIDType,
	'subscriptionIDData': decodeIA5String,
	'p-GWPLMNIdentifier': decodeIMSI,
	'startTime': decodeTimeStamp,
	'pDNConnectionChargingID': decodeInteger,
	'qCI': decodeInteger,
	'maxRequestedBandwithUL': decodeInteger,
	'maxRequestedBandwithDL': decodeInteger,
	'guaranteedBitrateUL': decodeInteger,
	'guaranteedBitrateDL': decodeInteger,
	'aRP': decodeInteger,
	'aPNAggregateMaxBitrateUL': decodeInteger,
	'aPNAggregateMaxBitrateDL': decodeInteger,
	'stopTime': decodeTimeStamp,
	'gsm0408Cause': decodeInteger,				#back here
	'failureHandlingContinue': decodeBoolean,
	'resultCode': decodeInteger
}

#def decodeValue

class ASN1Object():
	def __init__(self):
		self.tagClass = None
		self.tagType  = None
		self.tag      = None
		self.binValue = None
		self.headLen  = None
		self.idxStart = None
		self.idxEnd   = None
		self.valueLen = None
		self.objLen   = None
		self.value    = None
		self.tagName  = None
		self.child    = []
		self.path     = ()

	def prinObject(self):
		print ("tagClass: %s tagType %s tag %s valueLen %s idxEnd %s idxStart %s headLen %s objLen %s binValue %s" % 
			(self.tagClass, self.tagType, self.tag, self.valueLen, self.idxEnd, self.idxStart, self.headLen, self.objLen, binascii.hexlify(self.binValue)))

	def readNode(self, file, idx = 0):
		oct = 0
		origin_idx = idx
		obj = ASN1Object()
		obj.tagClass = ord(file[idx])&CLASS_MASK
		obj.tagType  = ord(file[idx])&FORM_MASK
		obj.tag      = ord(file[idx])&TAG_MASK

		if obj.tag == TAG_MASK:
			idx += 1
			obj.tag = ord(file[idx])&ETAG_MASK
			if obj.tag != ETAG_MASK:
				obj.tag = ord(file[idx])&FTAG_MASK
		idx += 1
		obj.valueLen = ord(file[idx])&LEN_XTND
		if obj.valueLen:
			oct = ord(file[idx])&LEN_MASK
			if oct == 1:
				obj.valueLen = struct.unpack('>B', file[idx+1:idx+oct+1])[0]
			elif oct == 2: #more than 16bit value not supported
				obj.valueLen = struct.unpack('>H', file[idx+1:idx+oct+1])[0]
		else:
			obj.valueLen = ord(file[idx])&LEN_MASK

		obj.idxEnd   = obj.valueLen + idx + oct + 1
		obj.idxStart = origin_idx
		obj.headLen  = obj.idxEnd - obj.valueLen - obj.idxStart
		obj.objLen   = obj.headLen + obj.valueLen
		obj.binValue = file[obj.idxStart+obj.headLen:obj.idxEnd]
		obj.path    += (obj.tag,)
		return obj

	def isChild(self):
		if len(self.child) != 0:
			print "have child", len(self.child)
			return len(self.child)
		else:
			print "no child", len(self.child)
			return None

class ASN1Tree(ASN1Object):
	def __init__(self):
		self.path = None
		self.tag = None
		self.name = None
		self.value = None
		self.tree = []

class CDRFile(ASN1Object, ASN1Tree):
	def __init__(self, cdrFile):
		self.file    = open(cdrFile).read()
		self.length  = len(self.file)
		self.idx     = 0
		self.records = []
		self.tree = []
		self.jsString = ""
		self.readRootNodes()
		self.parseRootNode()
		self.prettifyValues()

	def readRootNodes(self):
		while self.length != self.idx:
			obj = ASN1Object().readNode(self.file, self.idx)
			self.records.append(obj)
			self.idx = obj.idxEnd

	def parseRootNode(self):
		for i in self.records:
			idx =0
			while idx != i.valueLen:
				obj = i.readNode(i.binValue, idx)
				obj.path += (i.tag,)
				idx = obj.idxEnd
				i.child.append(obj)
				if obj.tagType == CONSTRUCTED:
					self.parseNodes(obj)

	def parseNodes(self, parent, idx = 0):
		obj = parent.readNode(parent.binValue, idx)
		obj.path += parent.path
		parent.child.append(obj)
		if obj.tagType == CONSTRUCTED:
			self.parseNodes(obj)
		if obj.idxEnd != parent.valueLen:
			self.parseNodes(parent, obj.idxEnd)

	#def traverse(self, rec):
	def printRawCDR(self, root):
		if root:
			for i in root.child:
				#print i.path
				if i.tagType != CONSTRUCTED:
					print "\t" * (len(i.path)-2), "tag:", i.tag, i.tagName, binascii.hexlify(i.binValue), "v:", i.value
				else:
					print "\t" * (len(i.path)-2), "tag:", i.tag, i.tagName, "-"
				self.printRawCDR(i)

	def traverse(self, root, elem):
		if root:
			for i in root.child:
				i.tagName = nodeName(i.path[::-1])
				if funcDict.get(i.tagName):
					i.value = funcDict[i.tagName](i.binValue)
					elem.tree.append([i.path[::-1], i.tagType, i.tag, i.tagName, i.value])
				else:
					elem.tree.append([i.path[::-1], i.tagType, i.tag, i.tagName, i.value])
				self.traverse(i, elem)

	def prettifyValues(self):
		for i in self.records:
			oid_tree = ASN1Tree()
			self.traverse(i, oid_tree)
			self.tree.append(oid_tree)

# EXTREMELY BOGUS!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	def renderJSON(self, i):
		json_str = "{"
		for x in range(len(i.tree)):
#			print i.tree[x][0]
			if x+1 < len(i.tree):
				if i.tree[x][1] != CONSTRUCTED:
					if len(i.tree[x+1][0]) < len(i.tree[x][0]):
						json_str += '"%s": %s' % (i.tree[x][3], i.tree[x][4])
						y = len(i.tree[x][0]) - len(i.tree[x+1][0])
						if i.tree[x+1][0] != (79, 34, 16) and i.tree[x+1][0] == (79, 35):
							json_str += "}" * (y-1) + "],"
						else:
							json_str += "}" * y + ","
					else:
						json_str += '"%s": %s,' % (i.tree[x][3], i.tree[x][4])
				elif i.tree[x][0] == (79, 34):
					json_str += '"%s":[' % (i.tree[x][3])
				elif i.tree[x][0] == (79, 34, 16):
					json_str += "{"
				else:
					json_str += '"%s":{' % (i.tree[x][3])
			else:
				json_str += '"%s": %s}' % (i.tree[x][3], i.tree[x][4])
		#print json_str
		return json_str

datefmt = ["timeOfLastUsage", "timeOfFirstUsage", "timeOfReport", "startTime", "stopTime", "recordOpeningTime"]
longfmt = ["datavolumeFBCDownlink", "datavolumeFBCUplink"]

def fmt_hook(json_dict):
	for (key, value) in json_dict.items():
		#print key, value
		if key in datefmt:
			json_dict[key] = parser.parse(value, yearfirst=True)
		if key in longfmt:
			json_dict[key] = long(value)
	return json_dict

client = MongoClient('localhost', 27017)
db = client.ggsn_cdr

#cdr = CDRFile(sys.argv[1])
#print json.loads(cdr.renderJSON(cdr.tree[0]), object_hook=datetime_hook)
#for i in cdr.tree:
	#print json.loads(cdr.renderJSON(i), object_hook=fmt_hook)
	#db.cdr_t.insert_one(json.loads(cdr.renderJSON(i), object_hook=fmt_hook))
#for i in cdr.records:
#	print "\nCDR:", cdr.records.index(i)
#	cdr.printRawCDR(i)
#print cdr.renderJSON()
	#print cdr.jsString
#for i in reversed(range(0, 33)):
#	print 2**i, i


for filename in os.listdir(sys.argv[1]):
	if filename.endswith(".t"): 
		print filename, "processed"
		cdr = CDRFile(os.path.join(sys.argv[1], filename))
		for i in cdr.tree:
			db.ggsn_cdr.insert_one(json.loads(cdr.renderJSON(i), object_hook=fmt_hook))
	else:
		continue

#!/usr/bin/python 

from __future__ import with_statement
import string
import time
from time import localtime
import os
import sys

verbose=0
if len(sys.argv) == 2:
	if sys.argv[1] == '-v':
		verbose=1

print "IPS(Interactive firewall) Grzegorz Kuczyński\n"

print "Ready rule.ips..."
find_log = {}
list_to_dict = []
with open("/root/rule.ips") as ips_rule_file:
	for line in ips_rule_file:
		if (line[0] == '#') or (line == '\n'):
			continue
		print line
		name,find,keyval,iprule = line.split(';;')
		find1,find2,find3 = find.split(',')
		keyl = []
		for key in keyval.split(';'):
			k,b1,b2 = key.split(',')
			tmp = (k,b1,b2)
			keyl.append(tmp)
		timeline = []
		ipt_rule,param,maxcount,timeline = iprule.split(';')
		paraml = param.split(',')
		rdata = []
		rdata.append((find1,find2,find3))
		rdata.append(keyl)
		ipt_rulel = []
		ipt_rulel.append(ipt_rule)
		for par in param.split(','):
			ipt_rulel.append(int(par))
		rdata.append(ipt_rulel)
		rdata.append(int(maxcount))
		rdata.append(timeline.replace('\n',''))
		list_to_dict.append((name,rdata))
	find_log = dict(list_to_dict)
ips_rule_file.close()
if verbose: 
	print "find_log:" 
	print find_log

print "\nReady ipt_rule.sh exist iptables rule..."
exist_ip_rule = []
with open("/root/ipt_rule.sh") as rule_file:
	for line in rule_file:
		print line.replace('\n','')
		exist_ip_rule.append(line)
rule_file.close()
if verbose: 
	print "exist_ip_rule:" 
	print exist_ip_rule



def get_value_from_key(text,key,between1,between2,start=0):
	_pos_start = text.find(key,start)
	#_begin = search_char_count(between1,1,text,_pos_start) zmiana
	_begin = search_char_count(between1,1,text,_pos_start+len(key))
	_end = search_char_count(between2,1,text,_begin+1)
	return text[_begin+1:_end]

def search_char_count(char,count,text,start=0):
	_number=start
	for i in range(count):
		_number = text.find(char,_number)
		if _number != -1:
			if i+1 < count:
				_number += 1
	return _number


def analyzer(line,year,month,day,hour,minute,second):
	if verbose: print "\nlog:\n"+line
	global find_log
	global exist_ip_rule
	global exist_ip_rule_count
	for sig, sig_data in find_log.iteritems():
		ident = sig_data[0]
		ident_true, ident_count = 0, 0
		if line.find(ident[0]) != -1:
			if ident[1] != 'NULL':
				if line.find(ident[1]) != -1:
					if ident[2] != 'NULL':
						if line.find(ident[2]) != -1:
							ident_true, ident_true = 1, 3
					else:
						ident_true, ident_count = 1, 2
			else:
				ident_true, ident_count = 1, 1
		if ident_true:
			val_key_item = sig_data[1]
			val_key_count = len(val_key_item)
			val_key = []
			for n_key in range(val_key_count):
				key, between1, between2 = val_key_item[n_key]
				val_key.append(get_value_from_key(line,key,between1,between2))
			ip_exist = 0
			sig_data_n = 5
			timel = []
			for _sig,ip,ip_count,timel in sig_data[5:]:
				if ip == val_key[0] and _sig == sig:
					after = 0
					if ip_count < sig_data[3]:
						ip_count += 1
						time = localtime()
						timel.append(str(time[3])+":"+str(time[4])+":"+str(time[5]))
						sig_data[sig_data_n] = sig,ip,ip_count,timel
						after=1
					if ip_count == sig_data[3]:
						if not after:
							time = localtime()
							sig,ip,ip_count,timel = sig_data[sig_data_n]
							timel.pop(0)
							timel.append(str(time[3])+":"+str(time[4])+":"+str(time[5]))
							sig_data[sig_data_n] = sig,ip,ip_count,timel
						
						sig,ip,ip_count,timel = sig_data[sig_data_n]
						ths,tms,tss=str(timel[0]).split(':')
						the,tme,tse=str(timel[ip_count-1]).split(':')

						if int(tse) < int(tss):
							ts = int(tse) + (60-int(tss))
							tms = int(tms)+1
						else:
							ts = int(tse) - int(tss)
						
						if int(tme) < int(tms):
							tm = int(tme) + (60-int(tms))
							ths = int(ths)+1
						else:
							tm = int(tme) - int(tms)
						
						if int(the) < int(ths):
							th = int(the) + (23-int(ths))
						else:
							th = int(the) - int(ths)
						
						if verbose: print "timeline: " + str(th)+":"+str(tm)+":"+str(ts) + " in time " + str(sig_data[4])
						
						_h,_m,_s=str(sig_data[4]).split(':')

						if ((th < int(_h)) or (tm < int(_m))) or ((th == int(_h)) and (tm == int(_m)) and (ts < int(_s))):
							if verbose: print "timeline ok"
							rule_def = sig_data[2]
							param_count = len(rule_def)
							rule = rule_def[0]
							full_rule = ''
							sh_rule = ''
							rule_part = rule.split("param")
							n_param = 1
							for part in rule_part:
								if n_param != param_count:
									full_rule += part + val_key[rule_def[n_param]-1]
								else:
									full_rule += part
								n_param += 1
							sh_rule = '/sbin/' + full_rule
							full_rule += '\n'
							ip_rule_exist = 0
							for ip_rule in exist_ip_rule:
								if ip_rule == full_rule:
									ip_rule_exist = 1
									log = '\nIPS ' + year + '.' +  month + '.' + day + ' ' + hour + ':' +  minute + ':' + second + ' Rule exist: ' + ip_rule.replace('\n','') + ' [n=' + str(sig_data[3]) + ' ip=' + str(val_key[0]) +  " timeline: " + str(th)+":"+str(tm)+":"+str(ts) + " in time " + str(sig_data[4]) + "]"
									print log.replace('\n','')
									file_log = open('./ips_activate.log','a')
									file_log.write(log)
									file_log.close()
									os.system("tail -n 1 ./ips_activate.log | mail -s IPS-info:exist admin@___.pl") # dodano
							if not ip_rule_exist:
								log = '\nIPS ' + year + '.' +  month + '.' + day + ' ' + hour + ':' +  minute + ':' + second + ' '  + sig + ': ' + full_rule.replace('\n','') + ' n=' + str(sig_data[3]) + ' ip=' + str(val_key[0]) +  " [timeline: " + str(th)+":"+str(tm)+":"+str(ts) + " in time " + str(sig_data[4]) + "]"
								print '** ' + log.replace('\n','')
								os.system(sh_rule)
								exist_ip_rule.append(full_rule)
								print "Add rule in ipt_rule.sh"
								file_rule = open('./ipt_rule.sh','a')
								file_rule.write(full_rule)
								file_rule.close()
								file_log = open('./ips_activate.log','a')
								file_log.write(log)
								file_log.close()
								os.system("tail -n 1 ./ips_activate.log | mail -s IPS-info:add admin@___.pl") # dodano
					ip_exist = 1
					break
				sig_data_n += 1
			if not ip_exist:
				item = val_key_item[0]
				time = localtime()
				tl = []
				tl.append(str(time[3])+":"+str(time[4])+":"+str(time[5]))
				tmp = (sig,get_value_from_key(line,item[0],item[1],item[2]),1,tl)
				sig_data.append(tmp)
		if verbose:
			print "find_log:" 
			print find_log

print "\nReady /dev/ips pipe..."
pipe = open('/dev/ips')
while 1:
	try:
		line = pipe.readline()
		date = localtime()
		analyzer(line,str(date[0]),str(date[1]),str(date[2]),str(date[3]),str(date[4]),str(date[5]))
		if 0 == line.find("stop"): 
			print '\nStop signal in /dev/ips'
			break
	except KeyboardInterrupt, e:
		print "\nQuit in Ctrl-C"
		break

pipe.close()
exit()




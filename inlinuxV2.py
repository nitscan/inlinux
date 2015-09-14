#!/usr/bin/python
# -*- coding:utf-8 -*-
import os
import getpass
import time
import socket
import re
'''for portscan'''
import threading
from Queue import Queue
import platform
import types
from subprocess import Popen, PIPE
'''for dns'''
import struct
import sys



__all__ = ['Thread', 'Threadpool', 'OK', 'FINISH', 'ERROR']

OK     = 0x0
FINISH = 0x1
ERROR  = 0x2

class Thread(threading.Thread):
	""
	def __init__(self, worker, task_queue, msg_queue, threadpool):
		super(Thread, self).__init__()
		self.worker = worker
		self.task_queue = task_queue
		self.threadpool = threadpool
		self.msg_queue = msg_queue

	def run(self):
		count = 0
		while True:
			self.threadpool.event.wait()
			if self.task_queue.empty():
				self.threadpool.InActiveOne()
				break
			task = self.task_queue.get()
			try:
				ret = self.worker(task)
				self.msg_queue.put((task, ret))
				if (not ret) and (ret[0] == FINISH):
					self.threadpool.clearQueue()
			except Exception as e:
				#print e
				#print task
				self.msg_queue.put((task, ERROR))
			finally:
				self.task_queue.task_done()


class Threadpool(object):
	""
	def __init__(self, worker, max_threads=10, thread=Thread,
					queue=Queue, lock=threading.RLock()):
		self.worker = worker
		self.thread = thread
		self.event = threading.Event()
		self.lock = lock
		self.task_queue = queue()
		self.msg_queue = queue()
		self.max_threads = max_threads
		self.active_threads = 0

		self.start()

	def add(self, tasks):
		for task in tasks:
			self.task_queue.put(task)
		len_tasks = self.task_queue.qsize()

		self.lock.acquire()
		create_tasks = self.max_threads - self.active_threads
		if len_tasks < create_tasks:
			create_tasks = len_tasks
		for i in xrange(create_tasks):
			self.ActiveOne()
		self.lock.release()

	def ActiveOne(self):
		self.lock.acquire()
		t = self.thread(self.worker, self.task_queue, self.msg_queue, self)
		t.setDaemon(True)
		t.start()
		self.active_threads += 1
		self.lock.release()

	def InActiveOne(self):
		self.lock.acquire()
		self.active_threads -= 1
		self.lock.release()

	def status(self):
		return self.task_queue.qsize(), self.active_threads

	def join(self):
		self.task_queue.join()

	def printmsg(self):
		pass

	def clearQueue(self):
		self.stop()
		while True:
			if self.task_queue.empty():
				break
			self.task_queue.get()
			self.task_queue.task_done()
		self.start()

	def start(self):
		self.event.set()

	def stop(self):
		self.event.clear()

class InScaner:
    def __init__(self,domain):
        self.NUM = 200
        self._re_IP = r'\d+\.\d+\.\d+\.\d+'
        self._re_startwithIP = r'^\d+\.\d+\.\d+\.\d+.*'
        self._re_network = r'^\d+\.\d+\.\d+'
        self.re_ip = re.compile(self._re_IP)
        self.re_startwithIP = re.compile(self._re_startwithIP)
        self.re_network = re.compile(self._re_network)
        try:
            self.host_ip = socket.gethostbyname(socket.gethostname())
        except:
            self.host_ip = '127.0.0.1'
        self.domain = domain
        self.path=os.getcwd()
        self.host_hostname = ''#os.popen('hostname').read()
        self.host_id = ''#os.popen('id').read()
        self.host_userlist=[]
        self.host_useronline=''
        self.host_last=''
        self.host_systemId = ''#os.popen('uname -a').read()
        self.host_systemversion = ''
        self.host_shadow = ''
        self.host_issue = ''
        self.host_bash_history = []
        self.host_services = '' 
        self.host_ESTABLISHEDlink = ''
        self.host_hackCmd = []
        self.host_complie = []
        
        self.dns=[]
        #self.dns=['58.83.193.214']
        self.etc_hosts=[]
        self.ifconfig=''
        self.arp=''
        self.route=''
        self.inerwww=''
        self.internetout=''
        self.keyip=[]
        self.keyipmaybe=[]
        self.networkmaybe=[]
        self.network = []#192.168.1.0
        self.q = Queue()
        self.s = Queue()
        self.networkIPlistA = []
        self.portlist = [21,22,23,25,53,80,81,139,443,445,1433,1521,3306,3398,5800,5900,5901,5902,6379,7001,7002,7070,8080,8081,8181,8888,9090,9200,27017,28018]
        self.networkIP_portOpen={}
        self.networkIP_weakPass={}
  
    def HostInfoGet(self):
        print u'###################host info####################'
        print u'#####host ip####'
        print self.host_ip+'\n'
        
        _hostcmdList = [
                        'hostname',#主机名
                        'id',      #用户id
                        '''
                        cat /etc/passwd|grep -v nologin|grep -v halt|grep -v shutdown|awk -F":" '{ print $1"|"$3"|"$4}'
                        ''',
                        'w',
                        'last',
                        'uname -a',
                        'cat /etc/issue',
                        ]
        
        print u'#####host name#####'
        self.host_hostname = os.popen(_hostcmdList[0]).read()
        print self.host_hostname
        
        print u'#####host id#####'
        self.host_id = os.popen(_hostcmdList[1]).read()
        print self.host_id
        
        print u'#####user list#####'
        userlist = os.popen(_hostcmdList[2]).read()
        self.host_userlist = userlist.split('\n')
        print userlist
        
        print u'#####user online#####'
        self.host_useronline = os.popen(_hostcmdList[3]).read()
        print self.host_useronline
        
        print u'#####login history#####'
        self.host_last = os.popen(_hostcmdList[4]).read()
        print self.host_last
        
        print u'#####linux ver#####'
        self.host_systemId = os.popen(_hostcmdList[5]).read()
        print self.host_systemId   
        
        print u'#####issue info#####'
        self.host_systemversion = os.popen(_hostcmdList[6]).read()
        print self.host_systemversion      
        
        print u'#####config info#####'

        _hostfileList = [
                        'cat /etc/shadow',
                        'cat ~/.bash_history',
                        'cat /root/.bash_history'
                        ]        
        print u'#####try to get shadow#####'
        self.host_shadow = os.popen(_hostfileList[0]).read()
        print self.host_shadow
        
        print u'#####to get .bash_history#####'
        self.host_bash_history.append(os.popen(_hostfileList[1]).read())
        self.host_bash_history.append(os.popen(_hostfileList[2]).read())
        print u'###sugjest output into file###'

            
        _servicecmdlist = [
                           'netstat -antlp',
                           '''
                           netstat -antlp | grep 'ESTABLISHED'
                           '''
                           ]
        print u'#####get listennig port and services#####'
        self.host_services = os.popen(_servicecmdlist[0]).read()
        print self.host_services
        
        print u'#####get Established network connection#####'
        self.host_ESTABLISHEDlink = os.popen(_servicecmdlist[1]).read()
        print self.host_ESTABLISHEDlink
        
        print u'#####list useable command#####'
        _host_hackSoft = [
                         'nmap',
                         'nc',
                         'netcat',
                         'wget',
                         'tcpdump',
                         'wireshark',
                         'rpm',
                         'yum',
                         'apt-get',
                         'ftp',
                         'ssh',
                         'telnet',
                         'scp',
                         'nslookup'
                         ]
        
        for cmd in _host_hackSoft:
            typecmd = 'type '+cmd+' >/dev/null'
            try:
                out = os.system(typecmd)
                if 0 == out:
                    self.host_hackCmd.append(cmd)
                    print '%s is ok' % cmd
            except:
                print '%s is unused' % cmd
        print u'###################get host info finished####################\n'
            
    def mgFileGet(self):
        print u'##########get password form file##########'
        
        print 'PHP'
        
        print 'tomcat'
        
        
        print 'apache'
        
        print 'struts'
        
        print 'jboss'
        
        print 'weblogic'
        
        print 'ftp'
        
        print 'ssh'
        
        print 'vnc'
        
        print 'mysql'
        
        print 'oracle'
        
        print 'search'
        
        pass
    
 
    def NetworkInfoGet(self):
        print u'####################get network info####################'
        _netfileListCat = [
                        'cat /etc/hosts',
                        'cat /etc/resolv.conf',
                        ]
            
        print u'######get dns ip#####'
        self.dns = self.re_ip.findall(os.popen(_netfileListCat[1]).read())
        for dns in self.dns:
            print dns
        
        print u'#####get hosts list#####'
        hosts = os.popen(_netfileListCat[0]).read().split('\n')
        for host in hosts:
            #print host
            _host=self.re_startwithIP.findall(host)
            if _host!=[]:
                self.etc_hosts += _host
        for host in self.etc_hosts:
            print host
            
        _netcmdList = [
                     '/sbin/ifconfig -a',
                     '/sbin/arp -n',
                     '/sbin/route -n',
                     'ping %s -c 2' % self.domain,
                     'ping 114.114.114.114 -c 2'

                     ]
        
        print u'#####get host interface and ip#####'
        self.ifconfig = os.popen(_netcmdList[0]).read()
        print self.ifconfig
        
        print u'#####get host arp list#####'
        self.arp = os.popen(_netcmdList[1]).read()
        print self.arp
        
        print u'#####get route#####'
        self.route = os.popen(_netcmdList[2]).read()
        print self.route
        
        print u'#####domain test#####'
        self.inerwww = os.popen(_netcmdList[3]).read()
        print self.inerwww
        
        print u'#####connect outside net test#####'
        self.internetout = os.popen(_netcmdList[4]).read()
        print self.internetout

            
        print u'#####DNS test#####'
        if self.dns == []:
            print u"!!sorry can't ip!!"
        else:
            for dnsip in self.dns:
                print u'###dns %s result###' % dnsip
                try:
                    self.GetDomainList(dnsip,self.domain)
                except:
                    print u'##dns test fail##'
        #获取DNS域传送信息
        print u'#####iner network exis#####'
        #先收集所有结果中的IP地址，去掉排除的ip地址后，把ip地址转换为网段，之后去重，最后保存
        ip = []
        keyip = []
        keyipmaybe =[]
        network = []
        keynetwork = []
        keynetworkmaybe = []
        
        _ex_ip =[
                 '127.0.0.1',
                 '0.0.0.0',
                 '255.255.255.255',
                 '255.255.255.0',
                 '255.255.0.0',
                 '255.0.0.0',
                 '127.0.1.1',
                 '8.8.8.8',
                 '114.114.114.114'
                 ]
        
        _iplistsearch = [
                           self.host_useronline,
                           self.host_last,
                           self.host_services,
                           self.host_ESTABLISHEDlink,
                           self.dns,
                           self.etc_hosts,
                           self.ifconfig,
                           self.arp,
                           self.route,
                           self.inerwww
                           ]
          
        _iplistsearchmaybe = [
                              self.host_bash_history
                              ]
      
        
        
        
        for text in _iplistsearchmaybe:
            if type(text) == type('1'):
                ip+=self.__getIPinStr(text)
            elif type(text) == type(['1']):
                for text2 in text:
                    ip+=self.__getIPinStr(text2)
        [keyipmaybe.append(ipnew) for ipnew in ip if ipnew not in (keyipmaybe+_ex_ip)]#ip地址处理
        self.keyipmaybe = keyipmaybe
        
        #变量中的IP并去重，去无效IP
        ip = []
        for text in _iplistsearch:
            if type(text) == type('1'):
                ip+=self.__getIPinStr(text)
            elif type(text) == type(['1']):
                for text2 in text:
                    ip+=self.__getIPinStr(text2)
        [keyip.append(ipnew) for ipnew in ip if ipnew not in (keyip+_ex_ip)]#ip地址处理
        #将IP地址转换为网段，并去重
        self.keyip = keyip
        
        _ex_network =[
                 '127.0.0.0'
                 ]
        
        for netip in self.keyipmaybe:
            network.append(self.__ip2network(netip))
            [keynetworkmaybe.append(net) for net in network if net not in keynetworkmaybe+_ex_network]
            
        network = []
        for netip in self.keyip:
            network.append(self.__ip2network(netip))
            [keynetwork.append(net) for net in network if net not in keynetwork+_ex_network]
        #筛选出私有IP地址
        _privatNet = [
                      '172',
                      '192',
                      '10'
                      ]
        print u"iner ip maybe exist:"
        for net in keynetworkmaybe:
            netsplit = net.split('.')
            if netsplit[0] in _privatNet:
                print net
                self.networkmaybe.append(net)
            
        print u"verfiy iner ip:"
        for net in keynetwork:
            netsplit = net.split('.')
            if netsplit[0] in _privatNet:
                print net
                self.network.append(net)
            
    
    def __ip2network(self,ip):
        return self.re_network.findall(ip)[0]+'.0'
        
    def __getIPinStr(self,string):
        ip = self.re_ip.findall(string)
        return ip
    
    __LEN_QUERY = 0    # Length of Query String
    def __gen_query(self,domain):
        import random
        TRANS_ID = random.randint(1, 65535)       # random ID
        FLAGS = 0; QDCOUNT = 1; ANCOUNT = 0; NSCOUNT = 0; ARCOUNT = 0
        data = struct.pack(
            '!HHHHHH',
            TRANS_ID, FLAGS,QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
            )
        query = ''
        for label in domain.strip().split('.'):
            query += struct.pack('!B', len(label)) + label.lower()
        query += '\x00'    # end of domain name
        data += query
        global __LEN_QUERY
        __LEN_QUERY = len(query)    # length of query section
        q_type = 252    # Type AXFR = 252
        q_class = 1    # CLASS IN
        data += struct.pack('!HH', q_type, q_class)
        data = struct.pack('!H', len(data) ) + data    # first 2 bytes should be length
        return data
    
    
    __OFFvSET = 0    # Response Data offset
    __TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
             12: 'PTR', 15: 'MX', 16: 'TXT',
             28: 'AAAA', 38: 'A6', 99: 'SPF',}
    
    def __decode(self,response):
        RCODE = struct.unpack('!H',response[2:4])[0] & 0b00001111
        if RCODE != 0:
            print 'Transfer Failed. %>_<%'
            sys.exit(-1)
        anwser_rrs = struct.unpack('!H', response[6:8] )[0]
        print '<< %d records in total >>' % anwser_rrs
        global __LEN_QUERY, __OFFSET
        __OFFSET = 12 + __LEN_QUERY + 4    # header = 12, type + class = 4
        while __OFFSET < len(response):
            name_offset = response[__OFFSET: __OFFSET + 2]    # 2 bytes
            name_offset = struct.unpack('!H', name_offset)[0]
            if name_offset > 0b1100000000000000:
                name = self.__get_name(response, name_offset - 0b1100000000000000, True)
            else:
                name = self.__get_name(response, __OFFSET)
            type = struct.unpack('!H', response[__OFFSET: __OFFSET+2] )[0]
            type = self.__TYPES.get(type, '')
            if type != 'A': print name.ljust(20), type.ljust(10)
            __OFFSET += 8    # type: 2 bytes, class: 2bytes, time to live: 4 bytes
            data_length = struct.unpack('!H', response[__OFFSET: __OFFSET+2] )[0]
            if data_length == 4 and type == 'A':
                ip = [str(num) for num in struct.unpack('!BBBB', response[__OFFSET+2: __OFFSET+6] ) ]
                print name.ljust(20), type.ljust(10), '.'.join(ip)
            __OFFSET += 2 + data_length
         
    # is_pointer: an name offset or not        
    def __get_name(self,response, name_offset, is_pointer=False):
        global __OFFSET
        labels = []
        while True:
            num = struct.unpack('B', response[name_offset])[0]
            if num == 0 or num > 128: break    # end with 0b00000000 or 0b1???????
            labels.append( response[name_offset + 1: name_offset + 1 + num] )
            name_offset += 1 + num
            if not is_pointer: __OFFSET += 1 + num
        name = '.'.join(labels)
        __OFFSET += 2    # 0x00
        return name
        
    def GetDomainList(self,dnsip,domain):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect( (dnsip, 53) )
        data = self.__gen_query(domain)
        s.send(data)
        s.settimeout(2.0)    # In case recv() blocked
        response = s.recv(4096)
        res_len = struct.unpack('!H', response[:2])[0]    # Response Content Length
        while len(response) < res_len:
            response += s.recv(4096)
        s.close()
        self.__decode(response[2:])
        
    def _ip2int(self,ip):
        return sum([256**j*int(i) for j,i in enumerate(ip.split('.')[::-1])])
    
    def _int2ip(self,intip):
        return '.'.join([str(intip/(256**i)%256) for i in range(3,-1,-1)])
    
    def __pingScan(self,ip):
        if platform.system() == 'Linux':
            p = Popen(['ping','-c 1',ip],stdout=PIPE)
            m = re.search('[1-9]+\sreceived', p.stdout.read())
            if m:
                self.networkIPlistA.append(ip)
        if platform.system()=='Windows':
            p = Popen('ping -n 1 ' + ip, stdout=PIPE)
            m = re.search('TTL=', p.stdout.read())
            if m:
                self.networkIPlistA.append(ip)

        return FINISH

    def __portScan(self,scan):
        portConnect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        portConnect.settimeout(100)
        try:
            portConnect.connect((scan[0],scan[1]))
            portConnect.close()
            self.networkIP_portOpen[scan[0]] += str(scan[1]) + ','
            #print self.networkIP_portOpen
        except Exception:
            print e
            
    def PortScan(self):
        print u'##########start port scanning################'
        print u'###alive host list###'
        if self.network == []:
            print u'ip is none...'
        else:
            #得到要ping的ip列表：
            _pinglist = []
            for network in self.network:
                for i in range(1,255):
                    _pinglist.append(self._int2ip(self._ip2int(network)+i))
        
            #开始执行
            _th_num = len(_pinglist)
            pingT  = Threadpool(self.__pingScan,200)
            pingT.add(_pinglist)
            pingT.join()

            #打印扫描存活IP列表结果,并给端口开发字典赋值
            for ip in self.networkIPlistA:
                self.networkIP_portOpen[ip]=''
                print ip
            
            print u'###port open..###'
            _scanlist = []
            for ip in self.networkIPlistA:
                for port in self.portlist:
                    _scanlist.append([ip,port])
            portT = Threadpool(self.__portScan,200)
            portT.add(_scanlist)
            portT.join()
            #print self.networkIP_portOpen
            #打印端口扫描结果：
            for ip in self.networkIPlistA:
                portlist = self.networkIP_portOpen[ip].split(',')
                #print portlist
                for port in portlist:
                    if port != '':
                        print '%s:%s' % (ip,port)
        #先ping，后直接进行TCP连接扫描
        print u'##########port scan finished##########'
        print u'####################network info finished####################\n'
        


if __name__ == '__main__':
    domain = sys.argv[1]
    out=InScaner(domain)
    out.HostInfoGet()
    out.NetworkInfoGet()
    out.PortScan()
    print u'###########total finised'
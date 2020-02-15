#!/usr/bin/python3
#Author: TAKEO

import subprocess , socket , urllib.request , json , sys, time , os,logging, threading, sqlite3 
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = 'hide'
import pygame , netifaces , platform 
from tqdm import tqdm
from scapy.all import *
from datetime import datetime
from terminaltables import AsciiTable
from colorama import Fore , Back, Style
from netaddr import IPNetwork , IPRange
from concurrent.futures import ThreadPoolExecutor

# TODO ADD argparse 


global host
global DEFAULT_In
global DEFAULT_G
global DEFAULT_GM
global NETMASK
global ip_range


if sys.platform != "linux":
	print('Must run on linux machine')
	sys.exit()
pass 

isroot = os.getuid() 
if isroot != 0:
	print("You are Not Root!")
	sys.exit()
else :  
	pass


#Define some colors 
fore = Fore 
RED = fore.RED 
GREEN = fore.GREEN
reset = Style.RESET_ALL
YELLOW = fore.YELLOW 


gateways = netifaces.gateways()
DEFAULT_G = gateways["default"][netifaces.AF_INET][0]
DEFAULT_In = gateways["default"][netifaces.AF_INET][1]
ifaddrs = netifaces.ifaddresses(DEFAULT_In)
NETMASK = ifaddrs[netifaces.AF_INET][0].get('netmask')
ip_range = IPs = [str(x) for x in IPNetwork(f"{DEFAULT_G}/{NETMASK}")]


def get_mac_by_ip(address):
	packet = ARP(op=1, pdst=address)
	response = sr1(packet, timeout=3, verbose=0, iface=DEFAULT_In)
	if response is not None :
		return response.hwsrc

DEFAULT_GM = get_mac_by_ip(DEFAULT_G) #getting the mac address of the gateway 


def MainMenu():
	print(GREEN,'\n'
		f'Gateway address     = {DEFAULT_G}\n'
		f'Gateway mac address = {DEFAULT_GM}\n'
		f'NETMASK             = {NETMASK}\n'
		f'Interface           = {DEFAULT_In}\n',reset)


class Main:

	def __init__(self):
		self.is_running = False 
		MainMenu()
		self.help()
		


	def Scan(self,ip):
		conn = sqlite3.connect("macvendor.db")
		cursor = conn.cursor()

		packet = ARP(op=1, pdst=ip)
		answer = sr1(packet, retry=0, timeout=2.5, verbose=0, iface=DEFAULT_In)

		if answer is not None :
			mac = answer.hwsrc
			mmac = mac[0:8].upper() # Get 16bit of the mac address and uppercase it

			cursor.execute("SELECT vendor FROM macvendor WHERE mac = '%s'" %(mmac))
			vendor = cursor.fetchone()
			if vendor is not None :
				v = vendor[0]
				hs = [self.ID,mac,ip,v]
				self.host.append(hs)
				self.ID += 1
			else : 
				pass



	def threads(self):
		self.ID = 1  # ID of the Host
		self.host = []# List Where we are going to append online hosts from Scan function
		with ThreadPoolExecutor(max_workers=75) as executor:
			self.online =[]
			iterator=tqdm(
				iterable=executor.map(self.Scan,ip_range),
				total = len(ip_range),
				ncols = 45,
				bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}'
	            )
			try :
				for t in iterator:
					if t is not None:
						self.online.append(t)
			except KeyboardInterrupt :
				iterator.close()
				print("Canceling..")
				self.choices()

	def hosts(self):
		try :
			print("\n\t\n")
			print("\t",len(self.host),"ONLINE HOSTS\n")
				

			self.table_data =[[
				f"{YELLOW}ID{reset}",
				f"{YELLOW}MAC{reset}",
				f"{YELLOW}IP {reset}",
				f"{YELLOW}VENDOR{reset}"
			]]

			self.table = AsciiTable(self.table_data)
			for h in sorted(self.host): 
				self.table_data.append(h)

			print(self.table.table)
			
		except AttributeError :
			print('[X] ONLINE HOSTS LIST IS EMPTY\n[+] Scan online hosts first press [0]')



	def IP_founder(self):
		external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
		print("YOUR EXTERNAL IP IS : ",external_ip)


	def ip_lookup(self):
		print('Ctrl + c to exit to the main menu')
		try : 
			while True :
				ip = input('Enter the IP here :')
				with urllib.request.urlopen(f'http://api.ipapi.com/api/{ip}?access_key=d6f48245085fb05889adab7397a5c34e&output=json') as url : 
					p = json.loads(url.read().decode())
					city = p['city']
					location = p['latitude'] , p['longitude']
					country = p['country_name']
					region = p['region_name']
					i = p['type']
					print("City : " , city , '\n'
						  "Country : ", country , '\n'
						  "Region : ", region , '\n'
						  "location : ",location , '\n'
						  "IP type: ", i)
		except KeyboardInterrupt : 
			self.choices()

	 
	def anti_spoof(self):

		gateway = subprocess.check_output(['ip','route'])
		g = gateway.translate(None, b'\r\n').decode().split()
		g0 = g[2]

		gateway_mac = subprocess.check_output(['arp','-vn',g0])
		m = gateway_mac.translate(None,b'\r\n').decode().split() 
		m0 = m[7]
		m1 = m[9]		
		e = re.findall('[A-Z][^A-Z]*',m1) #Finding out What interface is up s1 is the interface 
		s= ("").join(e)
		#interface
		s1 = m1.split(s)


		print(GREEN,'\n\n[+] Waiting for any ARP spoof attack! the service will be running in the Background\n\n',reset)

		while self.is_running :
			c = subprocess.check_output(['arp','-vn',g0],shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
			c1 = c.translate(None,b'\r\n').decode().split()
			self.c2 = c1[7]
			now = datetime.now()

			if self.c2 == m0 :
				continue

			else :
				print(RED,f"\n{now}" +":"+ f' WARNING ARP SPOOFED !! by {self.self.c2}',reset)
				pygame.mixer.init()
				s = pygame.mixer.Sound("warning.wav")
				s.play()
				self.logging() 
				time.sleep(5)
				s.stop()
				break
				self.choices()
				
		print(GREEN,'The Anti arp spoof service has been stoped you can try to run it again after cleaning your arp cache!!',reset)
		

	def threads1(self):
		thrs = threading.Thread(target=self.anti_spoof)
		self.is_running = True
		thrs.daemon= True
		thrs.start()

		
	def logging(self):
		logging.basicConfig(filename="arp_log.txt",
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)

		logging.info(f' WARNING ARP SPOOFED !! by {self.c2}')



	def help(self):
		print(f"{YELLOW}[0] Scan Network" '\n'
			  "[1] Show my External ip" "\n"
		      "[2] IP look up " "\n"
			  "[3] Run anti arp spoof " "\n"
			  "[4] Print Hosts " "\n"
		      "[help] For showing this help" "\n"
		      "[clear] clears terminal window \n"
			  f"[Ctrl+c]Exit{reset}" '\n')


	def choices(self):
		try : 
			w = input("NetScan >>  ")

			if w == "help" :
				self.help()
				self.choices()

			elif w == '0':
 				self.threads()
 				print("\n\n")
 				self.choices()
			
			elif w == "1":
				self.IP_founder()
				print("\n\n")
				self.choices()
			elif w == "2" : 
				self.ip_lookup()
				print("\n\n")
				self.choices()

			elif w == "3":
				self.threads1()
				time.sleep(1)
				print('\n\n')
				self.choices()

			elif w == '4' : 
				self.hosts()
				print('\n\n')
				self.choices()

			elif w == 'clear':
				os.system('clear')
				self.choices()


			else : 
				print('Error no command matches !')
				self.choices()
			

		except KeyboardInterrupt:
			try : 
				self.stop_loop()
			except Exception as e  : 
				pass 

			self.is_running = False
			print(YELLOW,'Exiting...')
			sys.exit()
	



if __name__=='__main__':
	main = Main()
	main.choices()
	

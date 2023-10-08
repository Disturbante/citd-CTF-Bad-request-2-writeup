#!/bin/env python3
import base64
import os

os.system("tshark -r exfil.pcap -Y 'ip.src==172.21.241.216' -T fields -e 'dns.qry.name' > dns_query.txt")


#inizializzo il dizionario flag
flag_chars = {}

print('[*]Exploit by Disturbante')

#apriamo il file creando un handle
with open('dns_query.txt','r')as f:
	#leggiamo ogni riga
	for line in f:
		#togliamo le parti superflue
		line = line.replace('.citd.dev\n','')
		#controlliamo il padding da aggiungere
		if (len(line)==7):
			line += '='
			#decodifichiamo la stringa
			decoded = base64.b32decode(line).decode()
			#controlliamo che non sia una stringa di riempimento
			if decoded[0].isdigit():
				separated = decoded.split(':')
				#aggiungiamola all'array dei caratteri della flag
				flag_chars[separated[0]] = separated[1]
		#ripetiamo il passaggio anche per i caratteri con padding diverso
		else:
			line += '==='
			decoded = base64.b32decode(line).decode()
			if decoded[0].isdigit():
				separated = decoded.split(':')
				flag_chars[separated[0]] = separated[1]
#infine ordiniamo l'array
flag_dict = dict(sorted(flag_chars.items()))
#creiamo una lista con indice crescente
flag_sorted = {k: flag_dict[k] for k in sorted(flag_dict, key=lambda x: int(x))}
#stampiamo i caratteri della flag tutti attaccati
print('[*]------------------------------->')
for valore in flag_sorted.values():
    print(valore, end='')
print('\n[*]------------------------------->')

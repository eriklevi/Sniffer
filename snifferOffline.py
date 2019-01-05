from scapy.all import *
import md5
dict = {}
dict_local = {}
dict_local_hash = {}
dict_global = {}
set_local = set()
set_global = set()
list_local = []

index = 0

def payload_parser(p):
    total = 0
    dict_tag = {}
    tags_list = []
    i = 0
    j = 2
    while total < len(p):
        tag = p[i:j]
        i += 2
        j += 2
        tag_length = int(p[i:j], 16)*2
        #i tag vendor specific possono essere ripetuti piu volte, dobbiamo inserirli in una lista
        if tag == 'DD':
            #attacco il vendor specific oui tag
            tag = tag + p[j + 6:j + 8]
        tags_list.append(tag)
        dict_tag[tag] = p[j:j + tag_length]
        total += tag_length + 4
        i = total
        j = i+2
    l=[dict_tag,tags_list]
    return l

class pack:
    def __init__(self, source_mac, payload):
        self.source_mac = source_mac
        result = ((int(source_mac[1], 16)) & 2) == 0
        if result == True:
            self.globalMac = True
        else:
            self.globalMac = False 
        self.payload = payload
        #rimuoviamo header e checksum
        mid = payload[48:len(payload)-8]
        #leng e la lunghezza delleventuale tag 00
        leng = int(mid[2:4],16)
        if leng == 0:
            #inizia gia con 0000
            self.IE = mid
        else:
            #rimuoviamo lssid e sostituiamo laparte iniziale con tutti 0
            self.IE = '0000'+mid[4+(leng*2):]
        res = payload_parser(self.IE)
        self.parsed_tags = res[0]
        self.tags_list = res[1]
        self.tags_string = ''.join(self.tags_list)


    def __str__(self):
        print('mac: '+ self.source_mac)
        print(self.payload)
        print(self.IE)
        print('')
        return ""

    def printTags(self):
        for element in self.parsed_tags:
            if element != 'DD':
                print element + " -> " + self.parsed_tags[element]
            else:
                for element2 in self.parsed_tags[element]:
                    print element + " -> " + element2

class similar_mac:
    def __init__(self, mac, similarity_score):
        self.mac = mac
        self.similarity_score = similarity_score
    
    def __str__(self):
        return '\t'+ self.mac + ' -> '+ str(self.similarity_score)

class similar_mac2:
    def __init__(self, mac, similarity_score,tags):
        self.mac = mac
        self.similarity_score = similarity_score
        self.tags = tags
    
    def __str__(self):
        return '\t'+ self.mac + ' -> '+ str(self.similarity_score) +'->'+self.tags

def myhexdump(x):
    x=str(x)
    l=len(x)
    i = 0
    elem = []
    while i < l:
        elem.append("%02X"%ord(x[i]))
        i+=1
    return ''.join(elem)

def compare_similarity(a, b):
    lena = len(a)
    lenb = len(b)
    localSimilarity = 0
    if lena == 0 or lenb == 0:
        return 0
    for j in range(min(lena,lenb)):
    #implementare comparazione bit per bit
        if a[j] == b[j]:
            localSimilarity += 1
        else:
            #sottraiamo uno per incrementare la diversita tra i vari risultati
            if localSimilarity > 1:
                #per evitare numeri negativi
                localSimilarity -= 1
    if lena > lenb:
        localSimilarity -= lena-lenb
    else:
        if lenb > lena:
            localSimilarity -= lenb-lena
    res = float(localSimilarity)/float(min(lena,lenb))
    if res < 0:
        res = 0
    return res

def compare_pack(a, b):
    if len(a.IE) != len(b.IE):
        return 0
    else:
        lena = len(a.IE)
        lenb = len(b.IE)
        localSimilarity = 0
        if lena == 0 or lenb == 0:
            return 0
        for j in range(min(lena,lenb)):
        #implementare comparazione bit per bit
            if a.IE[j] == b.IE[j]:
                localSimilarity += 1
            else:
                #sottraiamo uno per incrementare la diversita tra i vari risultati
                if localSimilarity > 1:
                    #per evitare numeri negativi
                    localSimilarity -= 1
        res = float(localSimilarity)/float(min(lena,lenb))
        #inp = raw_input("hola")
        return res

#compara tag per tag escludendo quelli solitamente piu similari tra di loro e quindi inutili
def compare_pack_mod1(a, b):
    count = 0
    res = 0
    for tag in a.parsed_tags:
        if tag != '00' and tag != '03' and tag != '2D' and tag != '6B' and tag != 'BF':
            if tag in b.parsed_tags:
                c = a.parsed_tags[tag]
                d = b.parsed_tags[tag]
                res += compare_similarity(c,d)
                count += 1
            else:
                count += 1
    count2 = 0
    res2 = 0
    for tag in b.parsed_tags:
        if tag != '00' and tag != '03' and tag != '2D' and tag != '6B' and tag != 'BF':
            if tag in a.parsed_tags:
                c = b.parsed_tags[tag]
                d = a.parsed_tags[tag]
                res2 += compare_similarity(d,c)
                count2 += 1
            else:
                count2 += 1
    res1 = float(res)/float(count)
    res2 = float(res2)/float(count2)
    return min(res1,res2)

def compare_pack_mod3(a, b):
    if a.tags_string == b.tags_string:
        if len(a.IE) == len(b.IE):
            return 1
    return 0

def compare_pack_mod2(a, b):
    if a.tags_string == b.tags_string:
        return 1
    return 0

def PacketHandler(pkt):
    global index
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.addr1 == 'ff:ff:ff:ff:ff:ff': 
                if pkt.type == 0 and pkt.subtype == 4:
                    try:
                        extra = pkt.notdecoded
                        potenza = extra[-2 : -1]
                        rssi = -(256-ord(potenza))
                    except:
                        rssi = -100
                    if rssi > -100:
                        hex_dump = myhexdump(pkt.payload)
                        dict[index] = pack(pkt.addr2,hex_dump)
                        index +=1

packets = rdpcap('./aulastudio20p.pcap')
for packet in packets:
    PacketHandler(packet)

for key in dict:
    if dict[key].globalMac == True:
        set_global.add(dict[key].source_mac)
    else:
        dict_local[dict[key].source_mac] = dict[key]
        list_local.append(dict[key].source_mac)
set_local = set(list_local)

print("indirizzi globali registrati %d" % len(set_global))
print("indirizzi locali registrati %d" % len(set_local))

dict2 = {}
while set_local:
    first = set_local.pop()
    pack = dict_local[first]
    dict2[first] = []
    for mac in dict_local:
        if mac != first:
            risultato = compare_pack(pack, dict_local[mac])
            if risultato != 0:
                dict2[first].append(similar_mac(mac, risultato))
                set_local.remove(mac)

print ("stima indirizzi univoci metodo vecchio %d" % len(dict2))

for key in dict2:
    print key
    for element in dict2[key]:
        print element



set_local = set(list_local)
dict2 = {}
while set_local:
    first = set_local.pop()
    pack = dict_local[first]
    dict2[first] = []
    for mac in dict_local:
        if mac != first:
            risultato = compare_pack_mod2(pack, dict_local[mac])
            if risultato != 0 and risultato > 0.9:
                dict2[first].append(similar_mac2(mac, risultato,dict_local[mac].tags_string))
                set_local.remove(mac)

print ("stima indirizzi univoci metodo mod2 %d" % len(dict2))

for key in dict2:
    print key
    for element in dict2[key]:
        print element

set_local = set(list_local)
dict2 = {}
while set_local:
    first = set_local.pop()
    pack = dict_local[first]
    dict2[first] = []
    for mac in dict_local:
        if mac != first:
            risultato = compare_pack_mod3(pack, dict_local[mac])
            if risultato != 0 and risultato > 0.9:
                dict2[first].append(similar_mac2(mac, risultato,dict_local[mac].tags_string))
                set_local.remove(mac)

print ("stima indirizzi univoci metodo mod3 %d" % len(dict2))

for key in dict2:
    print key
    for element in dict2[key]:
        print element

#prova con hash

def hashmd5(p):
    leng = str(len(p.IE))
    tags = p.tags_string
    if '01' in p.tags_list:
        tag01 = p.parsed_tags['01']
    else:
        tag01 = ''
    if '32' in p.tags_list:
        tag32 = p.parsed_tags['32']
    else:
        tag32 = ''
    if '7f' in p.tags_list:
        tag7f = p.parsed_tags['7f']
    else:
        tag7f = ''
    string = leng+tags+tag01+tag32+tag7f
    hash_md5 = md5.new(string).hexdigest()
    return hash_md5


for key in dict_local:
    dict_local_hash[key] = hashmd5(dict_local[key])
    print key, dict_local_hash[key]
from liono.common import settings
import subprocess,os,re,pyshark,time

def getsnortversion():
    vcheck  = subprocess.run(['snort','-V'],check=True,capture_output=True)
    vstr    = vcheck.stdout.decode("utf-8")
    match   = re.search("Version 3.",vstr)
    if match is None:
        v = 2
    else:
        v = vstr
    return v

def s3(rules,pcap):
    lua      = settings.projDir+"pigreplay/snortfiles/lua/snort.lua"
    # Run Snort3
    #test all s3 local rules
    if rules == 'lcl':
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,'-R', settings.rulesDir+'local.rules', '-A', 'alert_talos'], check=True, capture_output=True)

    #test with max-detect
    if rules == 'max':
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir,'--tweaks', 'max_detect', '-A','alert_talos'], check=True, capture_output=True)

    # test with sec over con
    if "sec" in rules:
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir,'--tweaks', 'security', '-A','alert_talos'], check=True, capture_output=True)

    # test with balanced
    if rules == 'bal':
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir,'--tweaks', 'balanced', '-A','alert_talos'], check=True, capture_output=True)

    # test with connectivity over security
    if rules == 'con':
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir,'--tweaks', 'connectivity', '-A', 'alert_talos'], check=True, capture_output=True)

    # test all snort3.rules downloaded
    if rules == 'all':
        snortrun = subprocess.run(['snort', '-q', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir, '-A', 'alert_talos'], check=True, capture_output=True)

    # test with sec over con & debug logs no -q
    if "debug" in rules:
        snortrun = subprocess.run(['snort', '-c', lua, '-r', settings.pcapDir + pcap,
                    '--rule-path', settings.rulesDir,'--tweaks', 'security', '-A','alert_talos'], check=True, capture_output=True)

    # write snort output to snort.log
    with open(settings.projDir+"pigreplay/snort.log", "w") as f:
        f.write(str(snortrun))
    f.close()
    res = readsnortlogs()
    return res

#Reads the snort alert log and prints the results or no results for the user
def readsnortlogs():
    results     = []                                               # snort++/3
    if os.path.isfile(settings.projDir+'pigreplay/snort.log'):
        # append the snort run log results
        with open(settings.projDir+'pigreplay/snort.log') as f:
            flines = f.readlines()
            f.close()
        list2str = ''.join(map(str, flines))
        newstr   = re.sub(r'.*snort.lua:','',list2str)
        teststr  = newstr.replace(r'\n', '\n')
        teststr  = re.sub(r'--------------------------------------------------','',teststr)
        teststr  = teststr.replace(r'\t','')
        teststr  = teststr.replace("', stderr=b'')",'\n')
        newlst   = teststr.split('\n')
        #del newlst[-1]
        #del newlst[-1]
        results.append("====SNORT3 RUNTIME LOG DATA====")
        for i in newlst:
            results.append(i)
        results.extend(["===Replay Edited Rule===",settings.rule])
    # remove the current snort.log & local.rules file for next replay
    try:
        os.remove(settings.projDir+'pigreplay/snort.log')
    except OSError:
        pass
    try:
        os.remove(settings.rulesDir+'local.rules')
    except:
        pass
    # print to cli for debugging
    #for r in results:
    #    print(r)
    return results                                              # return the snort.log data and alerts if any

#replay a packet wiht pyshark to get ip and protocol data
def replay(pcap):
    lcltime, proto, sip, dip, sport, dport = (None,None,None,None,None,None)
    data   = []
    replay = pyshark.FileCapture(settings.pcapDir+pcap)         # call tcpdump/tshark and replay packet
    if replay is None:
        return None
    else:
        for pkt in replay:
            lcltime = time.asctime(time.localtime(time.time()))
            proto   = "Protocol: {}".format(pkt.transport_layer)
            sip     = "Source IP: {}".format(pkt.ip.src)
            dip     = "Dest IP: {}".format(pkt.ip.dst)
            if "tcp" in pkt:
                sport = "Source Port: {}".format(pkt.tcp.srcport)
                dport = "Dest Port: {}".format(pkt.tcp.dstport)
            else:
                sport = "Source Port: {}".format(pkt.udp.srcport)
                dport = "Dest Port: {}".format(pkt.udp.dstport)
        data.extend((lcltime,proto,sip,dip,sport,dport))
        return data
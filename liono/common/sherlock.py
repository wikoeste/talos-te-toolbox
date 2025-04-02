from liono.common import settings
import json,requests,re,time,textwrap,threading,netaddr,subprocess,shlex
from terminaltables import AsciiTable
from ipaddress import ip_address
requests.packages.urllib3.disable_warnings()
###
def getSbrs(senderIP):
    #Check if the IP is ipv4 or ipv6
    is_not_empty = bool(senderIP)
    if is_not_empty is False:
        settings.guidconvert['sbrs'].append("Not a valid IPv4 or IPv6 address")
    elif netaddr.valid_ipv4(senderIP) is True:
        origRevip   = ip_address(senderIP).reverse_pointer
        revip = re.sub('.in-addr.arpa', '',origRevip)
        sbrsurl = revip+'.v1x2s.rf-adfe2ko9.senderbase.org'
        digcmd  = 'dig +noall +answer TXT '+sbrsurl
        proc    = subprocess.Popen(shlex.split(digcmd),stdout=subprocess.PIPE)
        out,err=proc.communicate()
        # Parse the returned dig data to dispaly the rules, and scores.
        split  = out.split()
        if len(split) >= 4:
            data   = split[4]
            data   = re.sub('b\'\"|\"\'', '',str(data))
            data   = re.sub('.=', '',str(data))
            data   = re.sub('\\|', ' ',str(data))
            res    = data.split(' ')
            date   = time.strftime("%Y-%m-%d %H:%M")
            date  = date
            ip    = senderIP
            score = res[1]
            rules = res[5]
            rules = ' '.join([rules[i:i+3] for i in range(0,len(rules), 3)])
        else:
            date    = time.strftime("%Y-%m-%d %H:%M")
            date    = date
            ip      = senderIP
            score   = 'N/A'
            rules   = 'None'
        #Check ip on public block lists
        pblCheck    = pbl(origRevip)
        #write sbrs data for analysis
        settings.guidconvert['rj'].append("SBRS Analysis {}".format(ip))
        settings.guidconvert['rj'].append("SBRS Score {}".format(score))
        settings.guidconvert['rj'].append("Rule Hits: {}".format(rules))
        settings.guidconvert['rj'].append("Block List: {}".format(pblCheck))
    elif netaddr.valid_ipv6(senderIP) is True:
        settings.guidconvert['rj'].append("SBRS IPV6 not supported")
    else:
        settings.guidconvert['rj'].append("SBRS - Not a valid IPv4 or IPv6 address")

def pbl(revip):
    blacklists = ("bl.spamcop.net","cbl.abuseat.org","pbl.spamhaus.org","sbl.spamhaus.org","xbl.spamhaus.org","dnsbl.invaluement.com")
    # Nslookup to check the Black Lists
    res        = []
    for bl in blacklists:
        digcmd  = 'dig +short '+str(revip)+'.'+str(bl)
        proc    = subprocess.Popen(shlex.split(digcmd),stdout=subprocess.PIPE)
        out,err = proc.communicate()
        decode = out.decode('utf-8')
        #test if an ip is returned from block list lookups
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',decode):
            res.append(bl)
        else:
            res = "Not Found"
    return res

def trackerDecodeRules(header,user,key,engine):
    url = 'https://sherlock.ironport.com/webapi/tracker/get_rules/?header='
    encoded = requests.utils.quote(str(header)) # created encoded header
    resp = requests.get(url+encoded, auth=(user,key),verify=False)
    code = resp.status_code
    if code == 200:
        js_result = resp.json()
        # print(json.dumps(js_result, indent=2))
        ESAprofile  = js_result["profile"]
        ims_score   = js_result["ims_score"]
        ims_enabled = str(js_result["ims_enabled"])
        of_enabled  = js_result["of_enabled"]
        if of_enabled is None:
            of_enabled = '--'
        spamScore   = js_result["spam_score"]
        of_cat      = js_result["of_cat"]
        if of_cat is None:
            of_cat  = '--'
        sdr_bucket  = js_result["sdr_bucket"]
        if sdr_bucket is None:
            sdr_bucket='--'
        vof_score   = js_result["vof_score"]
        caseRules   = js_result["ini_info"]["case_rules"]
        dfa         = js_result["ini_info"]["dfa_updates"]
        try:
            uridb   = js_result["ini_info"]["uridb_updates"]
        except KeyError:
            uridb   = None
        toc         = js_result["ini_info"]["toc_rules"]
        webinit     = js_result['webint_enabled']
        was,now,changed,rulename,desc = ([],[],[],[],[])
        #Check for rule hits on sample based on tracker header
        if "rules" in js_result:
            for rule in js_result['rules']:
                if (int(float(rule[1])) >= 0.80 or int(float(rule[1])) <= -0.5):
                    now.append(rule[1])
                    changed.append(rule[2])
                    was.append(rule[3])
                    rulename.append(rule[0])
                    desc.append(rule[4])
            #Create & print Table for rule results
            wasScores = "\n".join(was)
            nowScores = "\n".join(now)
            chgScores = "\n".join(changed)
            rulenames = "\n".join(rulename)
            descripts = "\n".join(str(i) for i in desc)

# called from server.py --> app.getrj
def reinjection(sample,user,key):
    rjURL   = 'https://sherlock.ironport.com/webapi/reinjection/search'
    params  = {'mids': sample}
    resp    = requests.get(rjURL, params=params, auth=(user,key), verify=False)
    status  = resp.status_code
    cids    = ',' ''.join(map(str, sample))
    cids.replace('"',"")
    cidlist = cids.split(",")
    #print(cidlist)
    if status == 200:
        print("Sherlock RJ Web API Success: {}".format(sample))
        jresp = resp.json()    
        #print(json.dumps(jresp, indent=2))
        ruleVers, subjwrap, sendingIP, egregious, vr_verd, t1, t2 = ('', '', '', '', '', '', '')
        senders, recipients, langs, keywords, flags, threads = ([], [], [], [], [], [])
        count = 1
        for i in jresp["data"]:
            ruleVers = i["rules_version"]
            if 'add_timestamp' in json.dumps(jresp):
                epoch = i["add_timestamp"]
            else:
                epoch = time.time()
            timestamp  = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(epoch))
            sampledate = re.sub(',', ' ', timestamp)
            sampledate = re.sub("r'\s+",'',sampledate)
            if 'subject' in json.dumps(jresp):
                subject = i["subject"]
                myWrap = textwrap.TextWrapper(width=50)
                subjwrap = myWrap.fill(text=subject)  # wrap subject line at 50 characters
            else:
                subjwrap = 'Error Parsing'
            if i["froms"] is not None:
                for s in i["froms"]:
                    senders.append(s)
            if i["tos"] is not None:
                for tos in i["tos"]:
                    recipients.append(tos)
            if i["languages_all"] is not None:
                for l in jresp['data'][0]['languages_all']:
                    langs.append(l)
            sendingIP = i["sender_ip"]
            if sendingIP is None:
                sendingIP = '0.0.0.0'
            egregious = i["egregious"]
            if egregious == 0:
                egregious = 'False'
            else:
                egregious = 'True'
            vr_verd = i["vr_verdict"]
            if vr_verd is not None:
                vr_verd = vr_verd
            else:
                vr_verd = '--'
            for f in i["flags"]:
                flags.append(f)
            for k in i["keywords_all"]:
                keywords.append(k)
            sbrs_esa = i["sbrs_esa"]
            sbrs_corp = i["sbrs_corpus"]
            sbrs_rinj = i["sbrs_reinject"]
            esaVerd = i["verdict_esa"]
            esaScor = i["score_esa"]
            if not (esaScor is None):
                esaScore = 0
            corpVerd = i["verdict_corpus"]
            corpScor = i["score_corpus"]
            rinjVerd = i["verdict_reinject"]
            rinjScor = i["score_reinject"]
            # Check Tracker Headers
            tracker_rinj = i["raw_tracker_reinject"]
            tracker_corpus = i["x-ironport-anti-spam-result"]
            tracker_esa = i["x-ipas-original-result"]
            if tracker_rinj is not None:
                rtracker = 'True'
            else:
                rtracker = 'False'
            if tracker_corpus is not None:
                ctracker = 'True'
            else:
                ctrtacker = 'False'
            if tracker_esa is not None:
                etracker = 'True'
            else:
                etracker = 'False'
            # Get and print tracker decoder header information (rule and config data)
            if tracker_esa is not None:
                engine = "ESA"
                t1 = threading.Thread(target=trackerDecodeRules, args=(tracker_esa,user,key,engine))
                threads.append(t1)
            elif tracker_corpus is not None:
                engine = "CASE"
                t1 = threading.Thread(target=trackerDecodeRules, args=(tracker_corpus,user,key,engine))
                threads.append(t1)
            elif rtracker is not None:
                engine = "Reinjection"
                t1 = threading.Thread(target=trackerDecodeRules, args=(tracker_rinj,user,key,engine))
                threads.append(t1)
            else:
                # Get empty tracker decoder table and print results
                noTracker_data = [['Tracker Decoder Data'],
                    ['No Data Available'],
                    ['No Valid Headers']]
                trackertable = AsciiTable(noTracker_data)
            # send back the rj results for html page
            # settings.guidconvert['rj'].append(sample)
            settings.guidconvert['rj'].append("Sample: {}".format(cidlist[count-1]))
            settings.guidconvert['rj'].append('Date:  {}'.format(sampledate))
            settings.guidconvert['rj'].append('Rule Version:' + str(ruleVers))
            settings.guidconvert['rj'].append('Subject: {}'.format(subject))
            settings.guidconvert['rj'].append('Senders: {}'.format(senders))
            settings.guidconvert['rj'].append('Recipients: {}'.format(recipients))
            settings.guidconvert['rj'].append('Sending IP: {}'.format(sendingIP))
            #Get SBRS IP threat data
            t2 = threading.Thread(target=getSbrs, args=(sendingIP,))
            threads.append(t2)
            if len(threads) >= 1:
                for t in threads:
                    t.start()
                    t.join()
            else:
                t2.start()
                t2.join()
            threads.clear()
            flagstring = " ".join(flags)
            settings.guidconvert['rj'].append('Flags: {}'.format(flagstring))
            kwordstring = " ".join(keywords)
            settings.guidconvert['rj'].append('Keywords: {}'.format(kwordstring))
            # write ipas tracker decoder data to variable for html file
            settings.guidconvert['rj'].extend(["ESA Score: {}".format(esaScor), "Verdict: {}".format(esaVerd),"THdr: {}".format(etracker),"SBRS Score: {}".format(sbrs_esa)])
            settings.guidconvert['rj'].extend(['Corpus Score: {}'.format(corpScor), "Verdict: {}".format(corpVerd),"Thdr: {}".format(ctracker),"SBRS Score {}".format(sbrs_corp)])
            settings.guidconvert['rj'].extend(['Reinj Score: {}'.format(rinjScor), "Verdict: {}".format(rinjVerd),"THdr: {}".format(rtracker),"SBRS Score: {}".format(sbrs_rinj)])
            settings.guidconvert['rj'].append('\n')
            ruleVers, subjwrap, sendingIP, egregious, vr_verd, t1, t2 = ('', '', '', '', '', '', '')
            senders, recipients, langs, keywords, flags, threads = ([], [], [], [], [], [])
            count+=1
    else:
        err = ("Sherlock API HTTP ERROR {}".format(status))
        print(err)
        settings.guidconvert['rj'].append(err)
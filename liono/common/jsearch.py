from liono.common import settings
from jira import JIRA
import requests,os,re,json,threading
from collections import Counter, OrderedDict

# search the various jira q's for any related tickets
def search(queue,qry):
    results     = None
    res         = []
    options     = {"server": "https://jira.talos.cisco.com"}
    jira        = JIRA(basic_auth=(settings.uname, settings.jkey), options=options)
    # Print the results by queue
    if queue == "COG":
        jqry = 'project=COG AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=100)
        print("=== COG Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "EERS":
        jqry = 'project=EERS AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===EERS Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "RESBZ":
        print(qry)
        jqry = 'project=RESBZ AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===RESBZ Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "THR":
        jqry = 'project= THR AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===THR Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue == "ALL":
        jqry    = 'project in (COG,EERS,THR,RESBZ) AND text ~ "'+str(qry)+'" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===All Jira Q's Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    # ERROR
    else:
        err = "Error, there is no ticket queue {}".format(queue)
        print(err)
        return err

def last7():
    tix,created,status,results = ([],)*4
    op,cl,reo       = 0,0,0
    jql             = None
    headers         = {'Content-type': 'application/json'}
    rqurl           = "https://jira.talos.cisco.com/rest/api/2/search"
    #assigned in the last 7
    jql = "?jql=project=COG and created >= -7d and assignee in (" + settings.uname + ")+"# AND status in (Open, Reopened, 'Pending Reporter', 'COG Investigating', 'Pending 3rd Party') order by updated DESC"
    resp = requests.get(rqurl+jql, headers=headers,auth=(settings.uname,settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        #print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            for i in jresp['issues']:
                tix.append(i['key'])
                datefrmt = re.sub("T.+", "", i['fields']['created'])
                created.append(datefrmt)
                status.append(i['fields']['status']['name'])
                if (i['fields']['status']['name'] == "Open"):
                    op+=1
                elif (i['fields']['status']['name'] == 'Resolved'):
                    cl+=1
                elif (i['fields']['status']['name'] == 'Reopened'):
                    reo+=1
                else:
                    pass

        return tix,op,cl,reo
    else:
        return None,0,0,0

def ques():
    proj    = ["COG","EERS","THR","BZ"]
    itype   = ["EMAIL","FILE","SNORT","WEB","OTHER","SBRS","ETD"]
    jql     = None
    headers = {'Content-type': 'application/json'}
    rqurl   = "https://jira.talos.cisco.com/rest/api/2/search"

    # submitted cog tix in last 7 days
    jql = "?jql=project=COG and created >= -7d&maxResults=500"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'cog':len(jresp['issues'])})
    else:
        settings.ques.update({'cog':0})

    # cog - type email
    jql = "?jql=project=COG AND issuetype = Email and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'email':len(jresp['issues'])})
    else:
        settings.ques.update({'email':0})

    # cog - type web+phish
    jql = "?jql=project=COG AND issuetype in (Phishtank, Web) and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'web':len(jresp['issues'])})
        else:
            settings.ques.update({'web':0})

    # cog - type endpoint/amp
    jql = "?jql=project=COG AND issuetype = Endpoint and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'amp': len(jresp['issues'])})
        else:
            settings.ques.update({'amp': 0})

    # cog - type snort
    jql = "?jql=project=COG AND issuetype = Vulnerability and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'snort': len(jresp['issues'])})
        else:
            settings.ques.update({'snort': 0})
    else:
        print("HTTP ERR: "+resp.status_code)

    # cog - type sbrs
    jql = "?jql=project=COG AND issuetype = SBRS and created >= -7d AND assignee in (membersOf(cog_users))"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'sbrs': len(jresp['issues'])})
        else:
            settings.ques.update({'sbrs': 0})

    # cog - type other
    jql = "?jql=project=COG AND issuetype in (Anti-Virus, Mailer, Other) and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'other': len(jresp['issues'])})
        else:
            settings.ques.update({'other': 0})

    closed    = "?jql=project=COG AND status in (Resolved, Closed) AND created >= -7D&maxResults=100"
    # closed in last 7
    rclsd = requests.get(rqurl + closed, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if rclsd.status_code == 200:
        jresp = rclsd.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print('closed ' + str(len(jresp['issues'])))
            settings.ques.update({'closed': len(jresp['issues'])})
        else:
            settings.ques.update({'closed': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # still open last 7
    notclosed = "?jql=project=COG AND status not in (Resolved, Closed) AND created >= -7D&maxResults=100"
    ropen = requests.get(rqurl + notclosed, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if ropen.status_code == 200:
        jresp = ropen.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print('not closed ', str(len(jresp['issues'])))
            settings.ques.update({'open': len(jresp['issues'])})
        else:
            settings.ques.update({'open': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # COG ESCALATED TO....
    # escalated by cog to ee,ntdr,thr,sdow
    jql = "?jql=project in (EERS, RESBZ, SDOCS, SDOW, THR) AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        print('escalations ='+ str(len(jresp['issues'])))
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            #print(len(jresp['issues']))
            settings.escalations.update({'total': len(jresp['issues'])})
        else:
            settings.escalations.update({'total': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # escalated to ee
    jql = "?jql=project=EERS AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'eers': len(jresp['issues'])})
        else:
            settings.escalations.update({'eers': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    #escalated to resbz
    jql  = "?jql=project = RESBZ AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'resbz': len(jresp['issues'])})
        else:
            settings.escalations.update({'resbz':0})
    else:
        print('HTTP ERR:', resp.status_code)

    #escalated to THR
    jql = "?jql=project = THR AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'thr': len(jresp['issues'])})
        else:
            settings.escalations.update({'thr': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd fn
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33092)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'fn': len(jresp['issues'])})
        else:
            settings.etd.update({'fn': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd fp
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33093)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'fp': len(jresp['issues'])})
        else:
            settings.etd.update({'fp': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd other
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33094)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'other': len(jresp['issues'])})
        else:
            settings.etd.update({'other': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # cog all p1 & p2 last 7
    jql = "?jql=project = COG AND priority in (P1, P2) AND created >= -7d ORDER BY created DESC&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'hot': len(jresp['issues'])})
        else:
            settings.ques.update({'hot': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # cases by company in last 7 days
    totl = 0
    comp = []
    jql  = "?jql=project = COG AND created >= -7d&maxResults=500"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            totl = len(jresp['issues'])
            for i in jresp['issues']:
                name = i["fields"]["customfield_13528"]
                comp.append(name)
            cust    = Counter(comp)
            srtcust = OrderedDict(cust.most_common())
            settings.monthly = srtcust
            settings.monthly.update({"Total":totl})
        else:
            settings.monthly = 0
    else:
        print('HTTP ERR:', resp.status_code)

    # open cases per TE engineer last 7
    te  = []
    jql = "?jql=project = COG AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            for i in jresp["issues"]:
                assignee = i["fields"]["assignee"]["displayName"]
                te.append(assignee)
            cog     = Counter(te)
            cogordr = OrderedDict(cog.most_common())
            settings.cog = cogordr
        else:
            settings.cog.update({'total': 0})
    else:
        print('HTTP ERR:', resp.status_code)
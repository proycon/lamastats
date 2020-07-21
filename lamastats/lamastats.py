#!/usr/bin/env python3

import sys
import argparse
from collections import defaultdict
from datetime import timedelta, date, datetime
import gzip
import json
import re
import apache_log_parser
import pygeoip
import os

gi = pygeoip.GeoIP(os.path.join(os.path.dirname(__file__),'GeoIP.dat'))

ignoreips = ['77.161.34.157'] #proycon@home, kobus@home,
internalips = ['127.0.0.1', '131.174.30.3','131.174.30.4'] #localhost, spitfire, applejack
internalblocks = ['131.174.']

def ininternalblock(ip):
    for internalblock in internalblocks:
        if ip.startswith(internalblock):
            return True
    return False

class PythonObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        elif isinstance(obj, set):
            return {'_set': list(obj)}
        elif isinstance(obj, date):
            return {'_date': obj.strftime('%Y-%m-%d') }
        else:
            raise Exception("Unhandled type: ", type(obj))

def PythonObjectDecoder(dct):
    if '_set' in dct:
        return set(dct['_set'])
    if '_date' in dct:
        return datetime.strptime(dct['_date'], '%Y-%m-%d').date()
    return dct

def daterange(start_date, end_date):
    dates = []
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date,'%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date,'%Y-%m-%d').date()
    for n in range(int((end_date - start_date).days)+1):
        dates.append(start_date + timedelta(n))
    return dates


def datestr(d):
    return d.strftime('%Y-%m-%d')


def parseuseragent(parsed_line):
    useragent = ""
    bot = False
    if 'request_header_user_agent' in parsed_line:
        useragent = parsed_line['request_header_user_agent']
    else:
        useragent = ""
    if useragent.lower().find("bot") != -1:
        #no bots
        print("- skipping bot: " + useragent, file=sys.stderr)
        bot = True
    elif useragent.lower().find("crawler") != -1:
        #no bots
        print("- skipping bot: " + useragent, file=sys.stderr)
        bot = True
    return useragent, bot

def loaddata(filename, data):
    if os.path.exists(filename):
        print("Loading previous data from " + filename,file=sys.stderr)
        loadeddata = json.load(open(filename,'r',encoding='utf-8'),object_hook=PythonObjectDecoder)
        for key in loadeddata.keys():
            if isinstance(data[key], dict):
                data[key].update(loadeddata[key]) #update preserving the defaultdict
            else:
                data[key] = loadeddata[key]

NGINX_PARSER = re.compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - "?(?P<remoteuser>[^\s]+)"? \[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST|PUT|DELETE) )(?P<request_url>.+)(HTTP\/1\.1")) (?P<status>\d{3}) (?P<bytessent>\d+) "?(?P<request_header_referer>[^"]+)"? "?(?P<request_header_user_agent>[^"]+)"? "?(?P<remote_host>.+)"?.*')
def nginx_line_parser(line):
    parsed_line = NGINX_PARSER.search(line).groupdict()
    parsed_line['time_received_datetimeobj'] = datetime.strptime(parsed_line['dateandtime'][:-6], "%d/%b/%Y:%H:%M:%S")
    parsed_line['request_method'] = parsed_line['request_url'][:parsed_line['request_url'].find(" ")]
    return parsed_line

def get_mode(logfile):
    mode = "apache"
    if logfile.startswith("apache:"):
        logfile = logfile[7:]
        mode = "apache"
    elif logfile.startswith("nginx:"):
        logfile = logfile[6:]
        mode = "nginx"
    return mode, logfile

def parse_line(line, mode):
    if mode == "apache":
        parsed_line = line_parser(line)
    elif mode == "nginx":
        parsed_line = nginx_line_parser(line)
    return parsed_line


def parselog(logfiles):
    data = {
        'names': set(),
        'hitsperday': defaultdict(dict),
        'typestats': defaultdict(lambda: defaultdict(int)),
        'platformstats': defaultdict(lambda: defaultdict(int)),
        'countrystats': defaultdict(lambda: defaultdict(int)),
        'totalhits': defaultdict(int),
        'lamachine': defaultdict(list),
        'lamachinetotal': 0,
        'latest': "",
    }
    loaddata('lamastats.json', data)
    latest = data['latest']
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")
    newhits = 0
    for logfile in logfiles:
        mode, logfile = get_mode(logfile)
        print("[parselog] Reading " + logfile + " (" + mode + ")",file=sys.stderr)
        if logfile[-3:] == '.gz':
            f = gzip.open(logfile,'rt',encoding='utf-8')
        else:
            f = open(logfile,'r',encoding='utf-8')
        for line in f:
            if line.find('lamachinetracker') != -1:
                parsed_line = parse_line(line, mode)
                if parsed_line['request_url'].startswith("/lamachinetracker.php/"):
                    args = parsed_line['request_url'][len("/lamachinetracker.php/"):]
                    args = args.split('/')
                    if len(args) == 4:
                        form, mode,stabledev,pythonversion = args
                    elif len(args) == 7:
                        form, mode,stabledev,pythonversion,os_id, distrib_id,distrib_release  = args
                    else:
                        print("- skipping invalid lamachinetracker: " + "/".join(args), file=sys.stderr)
                        continue

                    dt = parsed_line['time_received_datetimeobj']
                    dts = dt.strftime('%Y-%m-%d %H:%M:%S')
                    date = dt.date().strftime('%Y-%m-%d')
                    if dts < data['latest']:
                        continue #already counted
                    elif dts > latest:
                        latest = dts

                    useragent, bot = parseuseragent(parsed_line)
                    if bot:
                        continue

                    ip = parsed_line['remote_host']
                    if ip in ignoreips:
                        continue

                    country = 'unknown'
                    try:
                        country = gi.country_code_by_addr(ip)
                    except:
                        pass

                    hit = {
                        'form': form,
                        'mode': mode,
                        'stabledev': stabledev,
                        'pythonversion': pythonversion,
                        'ip': ip,
                        'os': os_id,
                        'distrib': distrib_id + ' ' + distrib_release,
                        'country':country,
                        'internal': ip in internalips or ininternalblock(ip),
                    }
                    #print("DEBUG hit:", hit,file=sys.stderr)

                    exists = False
                    if not date in data['lamachine']:
                        data['lamachine'][date] = []
                    for prevhit in data['lamachine'][date]:
                        if hit == prevhit:
                            exists = True
                            break

                    if not exists:
                        print("- Adding LaMachine hit: ", hit, file=sys.stderr)
                        newhits += 1
                        data['lamachine'][date].append(hit)
                        data['lamachinetotal'] += 1


            elif line.find('lamabadge') != -1:
                parsed_line = line_parser(line)
                #print("DEBUG parsed_line:",parsed_line, file=sys.stderr)
                if parsed_line['request_url'].startswith("/lamabadge.php/"):
                    name = parsed_line['request_url'][len("/lamabadge.php/"):]
                    if '/' in name or name.find('php') != -1  or ' ' in name or len(name) > 25:
                        #some poor man's validation
                        print("- skipping name " + name, file=sys.stderr)
                        continue

                    data['names'].add(name)
                    dt = parsed_line['time_received_datetimeobj']
                    dts = dt.strftime('%Y-%m-%d %H:%M:%S')
                    date = dt.date().strftime('%Y-%m-%d')
                    if dts < data['latest']:
                        continue #already counted
                    elif dts > latest:
                        latest = dts

                    if 'request_header_referer' in parsed_line:
                        referer = parsed_line['request_header_referer']
                    else:
                        referer = ""
                    ip = parsed_line['remote_host']
                    if ip in ignoreips:
                        continue

                    proxied = False
                    useragent, bot = parseuseragent(parsed_line)
                    if bot:
                        continue
                    if useragent.lower().find("camo") != -1 or useragent.lower().find("github") != -1:
                        hittype = 'github'
                        ip = '0.0.0.0' #irrelevant, proxied
                        proxied = True
                    elif referer.find("github.io") != -1:
                        hittype = 'ghpages'
                    else:
                        hittype = 'unknown'

                    if useragent.lower().find('android') != -1:
                        platform = 'android'
                    elif useragent.lower().find('linux') != -1:
                        platform = 'linux'
                    elif useragent.lower().find('ios') != -1:
                        platform = 'ios'
                    elif useragent.lower().find('mac os x') != -1:
                        platform = 'mac'
                    elif useragent.lower().find('bsd') != -1:
                        platform = 'bsd'
                    elif useragent.lower().find('windows') != -1:
                        platform = 'windows'
                    else:
                        platform = 'unknown'


                    country = 'unknown'
                    if not proxied:
                        try:
                            country = gi.country_code_by_addr(ip)
                        except:
                            pass

                    hit = {
                        'type': hittype,
                        'ip': ip,
                        'unique': hittype not in ('github',),
                        'platform': platform,
                        'country':country,
                        'internal': ip in internalips or ininternalblock(ip),
                    }
                    #print("DEBUG hit:", hit,file=sys.stderr)

                    exists = False
                    if not date in data['hitsperday'][name]:
                        data['hitsperday'][name][date] = []
                    elif not proxied:
                        for prevhit in data['hitsperday'][name][date]:
                            if hit == prevhit:
                                exists = True
                                break

                    if not exists:
                        newhits += 1
                        print("- Adding ", hit, file=sys.stderr)
                        data['hitsperday'][name][date].append(hit) #register the hit
                        if not name in data['totalhits']: data['totalhits'][name] = 0
                        data['totalhits'][name] += 1
                        if not hittype in data['typestats'][name]: data['typestats'][name][hittype] = 0
                        data['typestats'][name][hittype] += 1
                        if not platform in data['platformstats'][name]: data['platformstats'][name][platform] = 0
                        data['platformstats'][name][platform] += 1
                        if not country in data['countrystats'][name]: data['countrystats'][name][country] = 0
                        data['countrystats'][name][country] += 1

        f.close()
    data['latest'] = latest

    #sometimes writing breaks (not sure if due to script abortion), so we first buffer to a file, check integrity and then move it to the final place
    with open('lamastats.json.new','w',encoding='utf-8') as f:
        json.dump(data, f, cls=PythonObjectEncoder)
    #verify integrity
    with open('lamastats.json.new','r',encoding='utf-8') as f:
        try:
            json.load(f)
            os.rename('lamastats.json.new', 'lamastats.json')
        except:
            print("[parselog] lamastats.json INTEGRITY CHECK FAILED!",file=sys.stderr)

    print("[parselog] " + str(newhits) + " new hits",file=sys.stderr)
    return data


def parseclamlog(logfiles):
    data = {
        'names': set(),
        'projectsperday_internal': defaultdict(lambda: defaultdict(int)),
        'projectsperday': defaultdict(lambda: defaultdict(int)),
        'totalprojects': defaultdict(int),
        'latest': "",
    }
    loaddata('clamstats.json', data)
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")
    latest = data['latest']
    newhits = 0
    for logfile in sorted(logfiles):
        mode, logfile = get_mode(logfile)
        print("[parseclamlog] Reading " + logfile,file=sys.stderr)
        if logfile[-3:] == '.gz':
            f = gzip.open(logfile,'rt',encoding='utf-8')
        else:
            f = open(logfile,'r',encoding='utf-8')
        for line in f:
            found = False
            if line.find('/actions/') != -1:
                try:
                    parsed_line = parse_line(line, mode)
                except Exception as e:
                    print("ERROR!! UNABLE TO PARSE LINE : " ,line, "\nException:",e, file=sys.stderr)
                    continue
                #print("DEBUG parsed_line:",parsed_line, file=sys.stderr)
                if parsed_line['request_method'] in ('GET','POST','PUT') and parsed_line['status'] == '200':
                    fields = parsed_line['request_url'].strip('/').split('/')
                    if not fields or line.find('lamawebcheck') != -1:
                        continue
                    name = fields[0]
                    found = True
            elif line.find('PUT') != -1:
                try:
                    parsed_line = parse_line(line, mode)
                except Exception as e:
                    print("ERROR!! UNABLE TO PARSE LINE : " ,line, "\nException:",e, file=sys.stderr)
                    continue
                #print("DEBUG parsed_line:",parsed_line, file=sys.stderr)
                if parsed_line['request_method'] == 'PUT' and parsed_line['status'] == '201':
                    #found a 'project created' entry
                    fields = parsed_line['request_url'].strip('/').split('/')
                    if len(fields) != 2 or line.find('lamawebcheck') != -1:
                        continue
                    name = fields[0]
                    found = True
            if found:
                data['names'].add(name)
                dt = parsed_line['time_received_datetimeobj']
                dts = dt.strftime('%Y-%m-%d %H:%M:%S')
                date = dt.date().strftime('%Y-%m-%d')
                if dts < data['latest']:
                    continue #already counted
                elif dts > latest:
                    latest = dts

                ip = parsed_line['remote_host']
                if ip in ignoreips:
                    continue

                if ip in internalips or ininternalblock(ip):
                    if not date in data['projectsperday_internal'][name]: data['projectsperday_internal'][name][date] = 0
                    data['projectsperday_internal'][name][date] += 1
                newhits += 1
                if not date in data['projectsperday'][name]: data['projectsperday'][name][date] = 0
                data['projectsperday'][name][date] += 1
                if not name in data['totalprojects']: data['totalprojects'][name] = 0
                data['totalprojects'][name] += 1

    data['latest'] = latest
    #sometimes writing breaks (not sure if due to script abortion), so we first buffer to a file, check integrity and then move it to the final place
    with open('clamstats.json.new','w',encoding='utf-8') as f:
        json.dump(data, f, cls=PythonObjectEncoder)
    #verify integrity
    with open('clamstats.json.new','r',encoding='utf-8') as f:
        try:
            json.load(f)
            os.rename('clamstats.json.new', 'clamstats.json')
        except:
            print("[parselog] clamstats.json INTEGRITY CHECK FAILED!",file=sys.stderr)
    print("[parseclamlog] " + str(newhits) + " new hits",file=sys.stderr)
    return data

def parseflatlog(logfile):
    data = {
        'readdocumentsperday': defaultdict(int),
        'wrotedocumentsperday': defaultdict(int),
        'editsperday': defaultdict(int),
        'latest': "",
    }
    loaddata('flatstats.json', data)
    latest = data['latest']
    newhits = 0
    print("[parseflatlog] Reading " + logfile,file=sys.stderr)
    if logfile[-3:] == '.gz':
        f = gzip.open(logfile,'rt',encoding='utf-8')
    else:
        f = open(logfile,'r',encoding='utf-8')
    for line in f:
        if len(line) > 22 and line[20] == "-":
            date = line[:10] #date string only
            dts = line[:19] #full date time string
            if dts < data['latest']:
                continue #already counted
            elif dts > latest:
                latest = dts
            msg = line[22:]
            if msg.startswith("Loading "):
                newhits += 1
                if not date in data['readdocumentsperday']: data['readdocumentsperday'][date] = 0
                data['readdocumentsperday'][date] += 1
            elif msg.startswith("Saving "):
                newhits += 1
                if not date in data['wrotedocumentsperday']: data['wrotedocumentsperday'][date] = 0
                data['wrotedocumentsperday'][date] += 1
            elif msg.startswith("[QUERY ON ") and (msg.find("EDIT ") != -1 or msg.find("ADD ") != -1 or msg.find("DELETE ") != -1):
                newhits += 1
                if not date in data['editsperday']: data['editsperday'][date] = 0
                data['editsperday'][date] += 1
    data['latest'] = latest
    #sometimes writing breaks (not sure if due to script abortion), so we first buffer to a file, check integrity and then move it to the final place
    with open('flatstats.json.new','w',encoding='utf-8') as f:
        json.dump(data, f, cls=PythonObjectEncoder)
    #verify integrity
    with open('flatstats.json.new','r',encoding='utf-8') as f:
        try:
            json.load(f)
            os.rename('flatstats.json.new', 'flatstats.json')
        except:
            print("[parselog] flatstats.json INTEGRITY CHECK FAILED!",file=sys.stderr)
    print("[parseflatlog] " + str(newhits) + " new hits",file=sys.stderr)
    return data





def counttype(hits, hittype):
    count = 0
    for hit in hits:
        if hit['type'] == hittype:
            count += 1
    return str(count)

def countinternal(hits):
    count = 0
    for hit in hits:
        if hit['internal']:
            count += 1
    return str(count)



def graphlabels(startdate, enddate):
    out = []
    dates = daterange(startdate,enddate)
    for date in dates:
        if date.day == 1:
            if len(dates) > 365*2:
                out.append( date.strftime("%b\n%y") )
            elif len(dates) >= 365:
                out.append( date.strftime("%b") )
            else:
                out.append( date.strftime("%-d %b") )
        elif len(dates) <= 32:
            out.append( date.strftime("%-d") )
        elif date.day in (10,20) and len(dates) <= 60:
            out.append( date.strftime("%d") )
        else:
            out.append('')

    return json.dumps(out)


def startdates():
    for startdate, label in ( (date.today() - timedelta(31) , "Past month"),( date.today() - timedelta(365), "Past year"), (date(2016,1,1), "All time") ):
        yield startdate, label


def hitsperdaygraph(name, hitsperday):
    total = len(hitsperday)
    enddate = datetime.now().date()
    out = ""
    for i, (startdate, label) in enumerate(startdates()):
        dates = daterange(startdate,enddate)
        divisor = 1
        out +=  "<h4>" + label + "</h4>\n"
        out +=  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Total</span></strong> <em>(including other sources)</em>, <strong><span style=\"color: green\">Github</span></strong> <em>(not unique! no source info!)</em>, <strong><span style=\"color: blue\">Website</span></strong>, <strong><span style=\"color: red\">Radboud internal</span></strong></div>"
        out += "<div class=\"ct-chart ct-double-octave\" id=\"" + name + "-hitsperday-" + str(i) + "\"></div>\n"
        out += "<script>\n"
        out += "new Chartist.Line('#" +name + "-hitsperday-" + str(i) + "', {\n"
        out += "   labels: " + graphlabels(startdate,enddate) + ",\n"
        out += "   series: [\n"
        out += "        [" + ",".join((str(len(hitsperday.get(datestr(date),[]))) for date in dates)) + " ],\n"
        out += "        [" + ",".join((countinternal(hitsperday.get(datestr(date),{})) for date in dates)) + " ],\n"
        out += "        [" + ",".join((counttype(hitsperday.get(datestr(date),{}),'ghpages') for date in dates)) + " ],\n"
        out += "        [" + ",".join((counttype(hitsperday.get(datestr(date),{}),'github') for date in dates)) + " ]\n"
        out += "   ]\n"
        out += "},{ axisX: { scaleMinSpace: 20 }, axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
        out += "</script>\n"
    return out

def installsperdaygraph(hitsperday):
    total = len(hitsperday)
    enddate = datetime.now().date()
    out = ""
    for i, (startdate, label) in enumerate(startdates()):
        dates = daterange(startdate,enddate)
        labels = graphlabels(startdate, enddate)
        divisor = 1
        out +=  "<h4>" + label + "</h4>\n"
        out +=  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Total</span></strong>, <strong><span style=\"color: red\">Radboud internal</span></strong></div>"
        out += "<div class=\"ct-chart ct-double-octave\" id=\"lamachine-installsperday-" + str(i) + "\"></div>\n"
        out += "<script>\n"
        out += "new Chartist.Line('#lamachine-installsperday-" + str(i) + "', {\n"
        out += "   labels: " + labels + ",\n"
        out += "   series: [\n"
        out += "        [" + ",".join((str(len(hitsperday.get(datestr(date),[]))) for date in dates)) + " ],\n"
        out += "        [" + ",".join((countinternal(hitsperday.get(datestr(date),{})) for date in dates)) + " ]\n"
        out += "   ]\n"
        out += "},{ axisX: { divisor: " + str(divisor) + ", scaleMinSpace: 20 }, axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
        out += "</script>\n"
    return out

def projectsperdaygraph(name, projectsperday, projectsperday_internal):
    def counttype(hits, hittype):
        count = 0
        for hit in hits:
            if hit['type'] == hittype:
                count += 1
        return str(count)

    total = len(projectsperday)
    enddate = datetime.now().date()
    out = ""
    for i, (startdate, label) in enumerate(startdates()):
        dates = daterange(startdate,enddate)
        labels = graphlabels(startdate, enddate)
        divisor = 1
        out +=  "<h4>" + label + "</h4>\n"
        out +=  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Total new projects/actions per day</span></strong> <em>(including other sources)</em>, <strong><span style=\"color: red\">By internal sources</span></strong></div>"
        out += "<div class=\"ct-chart ct-double-octave\" id=\"" + name + "-projectsperday-" + str(i) + "\"></div>\n"
        out += "<script>\n"
        out += "new Chartist.Line('#" +name + "-projectsperday-" + str(i) + "', {\n"
        out += "   labels: " + labels + ",\n"
        out += "   series: [\n"
        out += "        [" + ",".join((str(projectsperday.get(datestr(date),0)) for date in dates)) + " ],\n"
        out += "        [" + ",".join((str(projectsperday_internal.get(datestr(date),0)) for date in dates)) + " ],\n"
        out += "   ]\n"
        out += "},{ axisX: { divisor: " + str(divisor) + ", scaleMinSpace: 20 }, axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
        out += "</script>\n"
    return out


def header():
    return """<html>
    <head>
        <title>Usage Reports</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/chartist.js/latest/chartist.min.css"/>
        <script src="https://cdn.jsdelivr.net/chartist.js/latest/chartist.min.js"></script>
        <style>
            body {
                font-family: sans;
                font-size: 10px;
                background: #eee;
                margin: 0px;
            }
            .ct-chart {
                display: block;
                width: 75%;
                max-width: 1000px;
                background: white;;
                margin-left: 50px;
            }
            h1, h2 {
                text-align: center;
                color: #413d5c;
            }
            h2 {
                font-variant: small-caps;
            }
            th.title {
                color: #939a61;
            }

            /* total */
            .ct-series-a .ct-line,
            .ct-series-a .ct-point {
                stroke: black;
                stroke-width: 2px;
              }

            /* github */
            .ct-series-b .ct-line,
            .ct-series-b .ct-point {
                stroke: red;
                stroke-width: 1px;
            }

            /* ghpages */
            .ct-series-c .ct-line,
            .ct-series-c .ct-point {
                stroke: blue;
                stroke-width: 1px;
            }
            /* internal */
            .ct-series-d .ct-line,
            .ct-series-d .ct-point {
                stroke: green;
                stroke-width: 1px;
            }

            .legend {
                margin-left: 100px;
                border: 1px #ddd dotted;
                background: #f2f3e9;
                width: 600px;
                text-align: center;
            }
            .legend em {
                font-size: 70%;
            }
            th,td { text-align: left; font-family: sans; font-size: 10px;}
            section {
                background: white;
                border: 2px #413d5c solid;
                border-radius: 25px;
                margin-left: 50px;
                margin-right: 50px;
                padding: 10px;
                margin-bottom: 20px;
                font-size: 10px;
            }
            #nav {
                background: #413d5c;
                color: white;
                text-align: center;
                font-size: 14px;
                padding-top: 5px;
                padding-bottom: 5px;
            }
            #nav ul {
                list-style-type: one;
                margin: 0;
                padding: 0;
            }
            #nav a, #nav a:link, #nav a:active {
                margin: 0px;
                padding: 3px;
                color: white;
                font-weight: bold;
            }
            td.avg {
                font-size: 85%;
                font-style: italic;
            }
            div.tablebox {
                float: right;
            }
        </style>
    </head>
    <body>
    """

def nav(track):
    s = '<div id="nav">'
    s += "<ul>"
    if 'badges' in track:
        s += '<li><a href="lamastats.html">Software Usage Statistics</a></li>'
    if 'flat' in track:
        s += '<li><a href="flatstats.html">FLAT Usage Statistics</a></li>'
    if 'clam' in track:
        s += '<li><a href="clamstats.html">Webservice Usage Statistics</a></li>'
    if 'lamachine' in track:
        s += '<li><a href="lamachinestats.html">LaMachine Usage Statistics</a></li>'
    s += "</ul>"
    s += "</div>"
    return s


def totaltable(data, hits_key='hitsperday', totalhits_key='totalhits'):
    pastdate7 = (datetime.now() - timedelta(7)).strftime('%Y-%m-%d')
    pastdate30 = (datetime.now() - timedelta(30)).strftime('%Y-%m-%d')
    out = "<table>\n"
    out += "<tr><th>Name</th><th>All time</th><th>Last 30 days</th><th>Avg per day</th><th>Last 7 days</th><th>Avg per day</th></tr>"
    for name in sorted(data['names'], key= lambda x: -1 * data[totalhits_key][x]):
        if name.strip() and data[totalhits_key][name] >= 10:
            out += "<tr><th><a href=\"#" + name + "\">" + name + "</a></th>"
            out += "<td>" + str(data[totalhits_key][name]) + "</td>"
            total7 = sum( ( v if isinstance(v,int) else len(v) for k,v in data[hits_key][name].items() if k >= pastdate7 ) )
            total30 = sum( ( v if isinstance(v, int) else len(v) for k,v in data[hits_key][name].items() if k >= pastdate30 ) )
            out += "<td>" + str(total30) + "</td>"
            out += "<td class=\"avg\">" + str(round(total30/30,1)) + "</td>"
            out += "<td>" + str(total7) + "</td>"
            out += "<td class=\"avg\">" + str(round(total7/7,1)) + "</td>"
            out += "</tr>\n"
    out += "</table>\n"
    return out

def outputreport(data, track):
    out = header()
    out += nav(track)
    out += "        <h1>LaMa Software Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>Total</h2>"
    out += totaltable(data,'hitsperday','totalhits')
    out += "</section>"
    for name in sorted(data['names'], key= lambda x: x.lower()):
        if name.strip() and data['totalhits'][name] >= 10:
            out += "<section>\n"
            out += "        <a name=\"" + name + "\"></a>"
            out += "        <h2>" + name + "</h2>\n"
            out += "        <h3>" + name + " - Visits per day</h3>"
            out += "<div class=\"tablebox\">" + toptable(data['hitsperday'][name],"country","Country",10, False) + "</div>"
            out += "<div class=\"tablebox\">" + toptable(data['hitsperday'][name],"platform","Platform",10, False) + "</div>"
            out += hitsperdaygraph(name, data['hitsperday'][name])
            out += "</section>\n"
    out += """    </body>
</html>"""
    return out

def outputclamreport(data, track):
    out = header()
    out += nav(track)
    out += "        <h1>CLAM Webservice Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>Total</h2>"
    out += totaltable(data,'projectsperday','totalprojects')
    out += "</section>"
    for name in sorted(data['names'], key= lambda x: x.lower()):
        out += "<section>\n"
        out += "        <a name=\"" + name + "\"></a>"
        out += "        <h2>" + name + "</h2>\n"
        out += "        <h3>" + name + " - New projects per day</h3>"
        out += projectsperdaygraph(name, data['projectsperday'][name], data['projectsperday_internal'][name])
        out += "</section>\n"
    out += """    </body>
</html>"""
    return out


def toptable(datalist, key, title, n=25, header=True):
    if header:
        out = "<h3>" + title + "</h3>"
    else:
        out = ""
    out += "<table>\n"
    d = defaultdict(int)
    for hits in datalist.values():
        for hit in hits:
            if key in hit:
                d[hit[key]] += 1
    total = sum(d.values())
    if not header and title:
        out += "<tr><th class=\"title\">" + title + "</th><th>Total</th></tr>"
    else:
        out += "<tr><th>Name</th><th>Total</th></tr>"
    for key, value in list(sorted(d.items(), key= lambda x: -1 * x[1]))[:n]:
        out += "<tr>"
        out += "<th>" + key+ "</th>"
        out += "<td>" + str(value) + " (" + str(round((value/total) * 100,2)) +  "%)</td>"
        out += "</tr>\n"
    out += "</table>\n"
    return out


def outputlamachinereport(data, track):
    out = header()
    out += nav(track)
    out += "        <h1>LaMachine Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>General Statistics</h2>"
    out += toptable(data['lamachine'], 'form','LaMachine Form')
    out += toptable(data['lamachine'], 'mode','LaMachine Mode')
    out += toptable(data['lamachine'], 'os','OS (type)')
    out += toptable(data['lamachine'], 'distrib','OS (exact)')
    out += toptable(data['lamachine'], 'pythonversion','Python Version')
    out += toptable(data['lamachine'], 'country','Country')
    out += "</section>"
    out += "<section>\n"
    out += "        <h3>Installations/updates per day</h3>"
    out += installsperdaygraph(data['lamachine'])
    out += "</section>\n"
    out += """    </body>
</html>"""
    return out

def outputflatreport(data, track):
    out = header(data)
    out += nav(track)
    out += "        <h1>FLAT Statistical Report</h1>\n"
    out += "<section>"
    out += "<section>\n"
    out += "        <h3>Documents per day</h3>"
    total = len(data['readdocumentsperday'])
    enddate = datetime.now().date()
    for i, (startdate, label) in enumerate(startdates()):
        dates = daterange(startdate,enddate)
        labels = graphlabels(startdate, enddate)
        divisor = 1
        out +=  "<h4>" + label + "</h4>\n"
        out +=  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Documents read per day</span></strong> , <strong><span style=\"color: red\">Documents written per day</span></strong></div>"
        out += "<div class=\"ct-chart ct-double-octave\" id=\"flat-documentsperday-" + str(i) + "\"></div>\n"
        out += "<script>\n"
        out += "new Chartist.Line('#flat-documentsperday-" + str(i) + "', {\n"
        out += "   labels: " + labels + ",\n"
        out += "   series: [\n"
        out += "        [" + ",".join((str(data['readdocumentsperday'].get(datestr(date),0)) for date in dates)) + " ],\n"
        out += "        [" + ",".join((str(data['wrotedocumentsperday'].get(datestr(date),0)) for date in dates)) + " ],\n"
        out += "   ]\n"
        out += "},{ axisX: { divisor: " + str(divisor) + ", scaleMinSpace: 20 }, axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
        out += "</script>\n"

    out += "</section>\n"
    out += "<section>\n"
    out += "        <h3>Edits/Annotations per day</h3>"
    total = len(data['readdocumentsperday'])
    enddate = datetime.now().date()
    for i, (startdate, label) in enumerate(startdates()):
        dates = daterange(startdate,enddate)
        labels = graphlabels(startdate, enddate)
        divisor = 1
        out +=  "<h4>" + label + "</h4>\n"
        out +=  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\"> annotations per day</span></strong></div>"
        out += "<div class=\"ct-chart ct-double-octave\" id=\"flat-editsperday-" + str(i) + "\"></div>\n"
        out += "<script>\n"
        out += "new Chartist.Line('#flat-editsperday-" + str(i) + "', {\n"
        out += "   labels: " + labels + ",\n"
        out += "   series: [\n"
        out += "        [" + ",".join((str(data['editsperday'].get(datestr(date),0)) for date in dates)) + " ],\n"
        out += "   ]\n"
        out += "},{ axisX: { divisor: " + str(divisor) + ", scaleMinSpace: 20 }, axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
        out += "</script>\n"

    out += "</section>\n"
    out += """    </body>
</html>"""
    return out

def main():
    global ignoreips, internalips, internalblocks
    parser = argparse.ArgumentParser(description="Generate Usage Reports", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d','--outputdir', type=str,help="Path to output directory", action='store',default="./",required=False)
    parser.add_argument('-F','--foliadocservelog', type=str,help="Path to FoLiA docserve log", action='store',required=False)
    parser.add_argument('--ignore','-i', type=str, help="Ignore requests from these IPs (space separated list)", required=False)
    parser.add_argument('--internal','-I', type=str, help="Count these IPs as internal (space separated list)", required=False, default="127.0.0.1")
    parser.add_argument('--internalblocks', type=str, help="Count these IP prefixes as internal (space separated list)", required=False)
    parser.add_argument('--tracklamachine',help="Track LaMachine stats", action='store_true', required=False)
    parser.add_argument('--trackbadges',help="Track software badges", action='store_true', required=False)
    parser.add_argument('--trackclam',help="Track clam webservices", action='store_true', required=False)
    parser.add_argument('--trackflat',help="Track FLAT (foliadocserve)", action='store_true', required=False)
    parser.add_argument('logfiles', nargs='+', help='Access logs, prepend filenames with "apache:" for apache, "nginx:" for nginx')
    args = parser.parse_args()

    if args.ignore:
        ignoreips = [ x for x in args.ignore.split(" ") if x ]
    if args.internal:
        internalips = [ x for x in args.internal.split(" ") if x ]
    if args.internalblocks:
        internalblocks = [ x for x in args.internalblocks.split(" ") if x ]

    outputdir = args.outputdir
    if outputdir[-1] != '/': outputdir += '/'


    track = set()
    if args.tracklamachine:
        track.add("lamachine")
    elif args.trackbadges:
        track.add("badges")
    elif args.trackclam:
        track.add("clam")
    elif args.trackflat or args.foliadocservelog:
        track.add("flat")
    if not track:
        print("No tracking options selected",file=sys.stderr)
        sys.exit(2)

    data = parselog(args.logfiles)

    if 'badges' in track:
        with open(outputdir + '/lamastats.html','w',encoding='utf-8') as f:
            print(outputreport(data, track), file=f)
    if 'lamachine' in track:
        with open(outputdir + '/lamachinestats.html','w',encoding='utf-8') as f:
            print(outputlamachinereport(data, track), file=f)

    if 'clam' in track:
        data = parseclamlog(args.logfiles)
        with open(outputdir + '/clamstats.html','w',encoding='utf-8') as f:
            print(outputclamreport(data, track), file=f)

    if 'flat' in track and args.foliadocservelog:
        data = parseflatlog(args.foliadocservelog)
        with open(outputdir + '/flatstats.html','w',encoding='utf-8') as f:
            print(outputflatreport(data, track), file=f)

if __name__ == '__main__':
    main()












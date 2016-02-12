#!/usr/bin/env python3

import sys
import argparse
from collections import defaultdict
from datetime import timedelta, date, datetime
import gzip
import json
import apache_log_parser
import pygeoip

gi = pygeoip.GeoIP('GeoIP.dat')

ignoreips = ('77.161.34.157',) #proycon@home
internalips = ('127.0.0.1', '131.174.30.3',)


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)+1):
        yield start_date + timedelta(n)


def parselog(logfiles):
    data = {
        'names': set(),
        'hitsperday': defaultdict(dict),
        'typestats': defaultdict(lambda: defaultdict(int)),
        'platformstats': defaultdict(lambda: defaultdict(int)),
        'countrystats': defaultdict(lambda: defaultdict(int)),
        'totalhits': defaultdict(int),
    }
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")
    for logfile in logfiles:
        print("[parselog] Reading " + logfile,file=sys.stderr)
        if logfile[-3:] == '.gz':
            f = gzip.open(logfile,'rt',encoding='utf-8')
        else:
            f = open(logfile,'r',encoding='utf-8')
        for line in f:
            if line.find('lamabadge') != -1:
                parsed_line = line_parser(line)
                #print("DEBUG parsed_line:",parsed_line, file=sys.stderr)
                if parsed_line['request_url'].startswith("/lamabadge.php/"):
                    name = parsed_line['request_url'][len("/lamabadge.php/"):]
                    if '/' in name or name.find('php') != -1  or ' ' in name or len(name) > 25:
                        #some poor man's validation
                        print("- skipping name " + name, file=sys.stderr)
                        continue

                    data['names'].add(name)
                    date = parsed_line['time_received_datetimeobj'].date()
                    if 'request_header_referer' in parsed_line:
                        referer = parsed_line['request_header_referer']
                    else:
                        referer = ""
                    if 'request_header_user_agent' in parsed_line:
                        useragent = parsed_line['request_header_user_agent']
                    else:
                        useragent = ""
                    ip = parsed_line['remote_host']
                    if ip in ignoreips:
                        continue

                    proxied = False
                    if useragent.lower().find("bot") != -1:
                        #no bots
                        print("- skipping bot: " + useragent, file=sys.stderr)
                        continue
                    elif useragent.lower().find("crawler") != -1:
                        #no bots
                        print("- skipping bot: " + useragent, file=sys.stderr)
                        continue
                    elif useragent.find("Camo Asset Proxy") != -1:
                        hittype = 'github'
                        ip = '0.0.0.0' #irrelevant, proxied
                        proxied = True
                    elif referer.find("pypi.python.org") != -1:
                        hittype = 'pypi'
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
                        'country':country
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
                        print("- Adding ", hit, file=sys.stderr)
                        data['hitsperday'][name][date].append(hit) #register the hit
                        data['totalhits'][name] += 1
                        data['typestats'][name][hittype] += 1
                        data['platformstats'][name][platform] += 1
                        data['countrystats'][name][country] += 1

        f.close()

    return data


def parseclamlog(logfiles):
    data = {
        'names': set(),
        'projectsperday_internal': defaultdict(lambda: defaultdict(int)),
        'projectsperday': defaultdict(lambda: defaultdict(int)),
        'totalprojects': defaultdict(int),
    }
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")
    for logfile in logfiles:
        print("[parseclamlog] Reading " + logfile,file=sys.stderr)
        if logfile[-3:] == '.gz':
            f = gzip.open(logfile,'rt',encoding='utf-8')
        else:
            f = open(logfile,'r',encoding='utf-8')
        for line in f:
            if line.find('PUT') != -1:
                parsed_line = line_parser(line)
                #print("DEBUG parsed_line:",parsed_line, file=sys.stderr)
                if parsed_line['request_method'] == 'PUT' and parsed_line['status'] == '201':
                    #found a 'project created' entry
                    fields = parsed_line['request_url'].strip('/').split('/')[0]
                    if len(fields) != 2:
                        continue
                    name = fields[0] 
                    data['names'].add(name)
                    date = parsed_line['time_received_datetimeobj'].date()

                    ip = parsed_line['remote_host']
                    if ip in ignoreips:
                        continue

                    if ip in internalips:
                        data['projectsperday_internal'][name][date] += 1
                    data['projectsperday'][name][date] += 1
                    data['totalprojects'][name] += 1

    return data

def hitsperdaygraph(name, hitsperday):
    def counttype(hits, hittype):
        count = 0
        for hit in hits:
            if hit['type'] == hittype:
                count += 1
        return str(count)

    total = len(hitsperday)
    startdate = date(2016,1,1) #min(hitsperday.keys())
    enddate = datetime.now().date()
    out =  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Total</span></strong> <em>(including other sources)</em>, <strong><span style=\"color: red\">Github</span></strong> <em>(not unique!)</em>, <strong><span style=\"color: blue\">Website</span></strong>, <strong><span style=\"color: green\">Python Package Index</span></strong></div>"
    out += "<div class=\"ct-chart ct-double-octave\" id=\"" + name + "-hitsperday\"></div>\n"
    out += "<script>\n"
    out += "new Chartist.Line('#" +name + "-hitsperday', {\n"
    out += "   labels: [" + ",".join(('"' +date.strftime("%d-%m")+'"' if date.day in (1,5,10,15,20,25) else '""' for date in daterange(startdate,enddate))) + " ],\n"
    out += "   series: [\n"
    out += "        [" + ",".join((str(len(hitsperday.get(date,[]))) for date in daterange(startdate,enddate))) + " ],\n"
    out += "        [" + ",".join((counttype(hitsperday.get(date,{}),'github') for date in daterange(startdate,enddate))) + " ],\n"
    out += "        [" + ",".join((counttype(hitsperday.get(date,{}),'ghpages') for date in daterange(startdate,enddate))) + " ],\n"
    out += "        [" + ",".join((counttype(hitsperday.get(date,{}),'pypi') for date in daterange(startdate,enddate))) + " ]\n"
    out += "   ]\n"
    out += "},{ axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
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
    startdate = date(2016,1,1) #min(projectsperday.keys())
    enddate = datetime.now().date()
    out =  "       <div class=\"legend\">Legend: <strong><span style=\"color: black\">Total new projects per day</span></strong> <em>(including other sources)</em>, <strong><span style=\"color: red\">By internal sources</span></strong></div>"
    out += "<div class=\"ct-chart ct-double-octave\" id=\"" + name + "-projectsperday\"></div>\n"
    out += "<script>\n"
    out += "new Chartist.Line('#" +name + "-projectsperday', {\n"
    out += "   labels: [" + ",".join(('"' +date.strftime("%d-%m")+'"' if date.day in (1,5,10,15,20,25) else '""' for date in daterange(startdate,enddate))) + " ],\n"
    out += "   series: [\n"
    out += "        [" + ",".join((str(projectsperday.get(date,0)) for date in daterange(startdate,enddate))) + " ],\n"
    out += "        [" + ",".join((str(projectsperday_internal.get(date,0)) for date in daterange(startdate,enddate))) + " ],\n"
    out += "   ]\n"
    out += "},{ axisY: { onlyInteger: true}, fullWidth: true, low: 0, lineSmooth: Chartist.Interpolation.cardinal({tension: 0.5, fillHoles: false}) } );\n"
    out += "</script>\n"
    return out


def header(data):
    return """<html>
    <head>
        <title>LaMa Software Statistical Report</title>
        <link rel="stylesheet" href="http://cdn.jsdelivr.net/chartist.js/latest/chartist.min.css"/>
        <script src="http://cdn.jsdelivr.net/chartist.js/latest/chartist.min.js"></script>
        <style>
            body {
                font-family: sans;
                font-size: 10px;
                background: url(https://webservices-lst.science.ru.nl/style/back.png) repeat;
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
                color: #939a61;
            }
            h2 {
                font-variant: small-caps;
            }

            /* total */
            .ct-series-a .ct-line,
            .ct-series-a .ct-point {
                stroke: black;
                stroke-width: 3px;
              }

            /* github */
            .ct-series-b .ct-line,
            .ct-series-b .ct-point {
                stroke: red;
                stroke-width: 2px;
            }

            /* ghpages */
            .ct-series-c .ct-line,
            .ct-series-c .ct-point {
                stroke: blue;
                stroke-width: 2px;
            }
            /*pypi */
            .ct-series-d .ct-line,
            .ct-series-d .ct-point {
                stroke: green;
                stroke-width: 2px;
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
            th { text-align: left; }
            section {
                background: white;
                border: 2px #d2de84 solid;
                border-radius: 25px;
                margin-left: 50px;
                margin-right: 50px;
                padding: 10px;
                margin-bottom: 20px;
            }
            #nav {
                background: #d2de84;
                color: white;
                text-align: center;
            }
            #nav a, #nav a:link, #nav a:active {
                margin: 0px;
                padding: 3px;
                color: black;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
    <div id="nav">
     [ <a href="lamastats.html">Software Statistics</a> | <a href="clamstats.html">Webservice Statistics</a> ]
    </div>
    """



def outputreport(data):
    out = header(data)
    out += "        <h1>LaMa Software Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>Total</h2>"
    out += "<table>\n"
    for name in sorted(data['names'], key= lambda x: -1 * data['totalhits'][x]):
        out += "<tr><th>" + name + "</th><td>" + str(data['totalhits'][name]) + "</td></tr>\n"
    out += "</table>\n"
    out += "</section>"
    for name in sorted(data['names'], key= lambda x: x.lower()):
        out += "<section>\n"
        out += "        <h2>" + name + "</h2>\n"
        out += "        <h3>" + name + " - Visits per day</h3>"
        out += hitsperdaygraph(name, data['hitsperday'][name])
        out += "</section>\n"
    out += """    </body>
</html>"""
    return out

def outputclamreport(data):
    out = header(data)
    out += "        <h1>CLAM Webservice Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>Total</h2>"
    out += "<table>\n"
    for name in sorted(data['names'], key= lambda x: -1 * data['totalprojects'][x]):
        out += "<tr><th>" + name + "</th><td>" + str(data['totalprojects'][name]) + "</td></tr>\n"
    out += "</table>\n"
    out += "</section>"
    for name in sorted(data['names'], key= lambda x: x.lower()):
        out += "<section>\n"
        out += "        <h2>" + name + "</h2>\n"
        out += "        <h3>" + name + " - New projects per day</h3>"
        out += projectsperdaygraph(name, data['projectsperday'][name], data['projectsperday_internal'][name])
        out += "</section>\n"
    out += """    </body>
</html>"""
    return out


def main():
    parser = argparse.ArgumentParser(description="Language Machines Software Statistical Analyser", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #parser.add_argument('--storeconst',dest='settype',help="", action='store_const',const='somevalue')
    parser.add_argument('-d','--outputdir', type=str,help="Path to output directory", action='store',default="./",required=False)
    #parser.add_argument('-i','--number',dest="num", type=int,help="", action='store',default="",required=False)
    parser.add_argument('logfiles', nargs='+', help='Apache access logs')
    args = parser.parse_args()

    outputdir = args.outputdir
    if outputdir[-1] != '/': outputdir += '/'

    data = parselog(args.logfiles)
    #with open(outputdir + '/lamastats.json','w',encoding='utf-8') as f:
    #    json.dump(data, f)
    with open(outputdir + '/lamastats.html','w',encoding='utf-8') as f:
        print(outputreport(data), file=f)

    data = parseclamlog(args.logfiles)
    with open(outputdir + '/clamstats.html','w',encoding='utf-8') as f:
        print(outputclamreport(data), file=f)



if __name__ == '__main__':
    main()












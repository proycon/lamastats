#!/usr/bin/env python3

import sys
import argparse
from collections import defaultdict
from datetime import timedelta, date, datetime
import apache_log_parser
import pygeoip

gi = pygeoip.GeoIP('GeoIP.dat')

ignoreips = ('77.161.34.157','127.0.0.1')


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)+1):
        yield start_date + timedelta(n)


def parselog(logfile):
    hitsperday = defaultdict(dict)
    typestats = defaultdict(lambda: defaultdict(int))
    platformstats = defaultdict(lambda: defaultdict(int))
    countrystats = defaultdict(lambda: defaultdict(int))
    totalhits = defaultdict(int)
    names = set()
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")
    with open(logfile,'r',encoding='utf-8') as f:
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

                    names.add(name)
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
                    if not date in hitsperday[name]:
                        hitsperday[name][date] = []
                    elif not proxied:
                        for prevhit in hitsperday[name][date]:
                            if hit == prevhit:
                                exists = True
                                break

                    if not exists:
                        print("- Adding ", hit, file=sys.stderr)
                        hitsperday[name][date].append(hit) #register the hit
                        totalhits[name] += 1
                        typestats[name][hittype] += 1
                        platformstats[name][platform] += 1
                        countrystats[name][country] += 1


    return names,hitsperday, typestats, platformstats, countrystats,totalhits



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





def outputreport(names, hitsperday, typestats, platformstats, countrystats,totalhits):
    out = """<html>
    <head>
        <title>LaMa Software Statistical Report</title>
        <link rel="stylesheet" href="//cdn.jsdelivr.net/chartist.js/latest/chartist.min.css"></link>
        <script src="//cdn.jsdelivr.net/chartist.js/latest/chartist.min.js"></script>
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
        </style>
    </head>
    <body>"""
    out += "        <h1>LaMa Software Statistical Report</h1>\n"
    out += "<section>"
    out += "<h2>Total</h2>"
    out += "<table>\n"
    for name in sorted(names, key= lambda x: -1 * totalhits[x]):
        out += "<tr><th>" + name + "</th><td>" + str(totalhits[name]) + "</td></tr>\n"
    out += "</table>\n"
    out += "</section>"
    for name in sorted(names, key= lambda x: x.lower()):
        out += "<section>\n"
        out += "        <h2>" + name + "</h2>\n"
        out += "        <h3>" + name + " - Visits per day</h3>"
        out += hitsperdaygraph(name, hitsperday[name])
        out += "</section>\n"
    out += """    </body>
</html>"""
    return out


def main():
    parser = argparse.ArgumentParser(description="Language Machines Software Statistica Analyser", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    #parser.add_argument('--storeconst',dest='settype',help="", action='store_const',const='somevalue')
    #parser.add_argument('-f','--dataset', type=str,help="", action='store',default="",required=False)
    #parser.add_argument('-i','--number',dest="num", type=int,help="", action='store',default="",required=False)
    parser.add_argument('logfile', type=str, help='Apache access log')
    args = parser.parse_args()

    names,hitsperday,typestats,platformstats,countrystats,totalhits = parselog(args.logfile)
    print(outputreport(names,hitsperday,typestats,platformstats,countrystats,totalhits))

if __name__ == '__main__':
    main()












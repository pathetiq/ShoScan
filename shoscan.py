"""
Author: PathetiQ
Based on emresaglam work : https://github.com/emresaglam/shodan-bulk-ip-query/blob/master/ipQuery.py
Changes:
- add export to csv
    - Add export of all data return
    - Add export of only (ip, port, protocol)
- add 1 sec delay per search (as stated by shodan documentation)
- rewrote with a main and some function
- Adjust the output to the console for "cuter" output + ascii
- updated shodan library
"""

import json
import shodan
import csv
import argparse
import time


def writeResults(results,outputFile,shortOutputFile):
    '''
    :param results: shodan scan resulsts
    :param outputFile: output file name to write to
    :param shortOutputFile: prefix to filename of the shoirt version
    '''
    short = results['short']
    full = results['full']

    # write short version
    with open(shortOutputFile+"."+outputFile, mode='w') as out_file:
        out_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        for ip in short:
            try:
                for i in range(len(short[ip]['port'])):
                    out_writer.writerow([ip,short[ip]['port'][i],short[ip]['protocol'][i]])
            except KeyError as e:
                continue

    # write full version
    with open(outputFile, mode='w') as out_file:
        out_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        for ip in full:
            items = []
            try:

                for item in full[ip]['all']:
                    for i in item:
                        out_writer.writerow([ip,i,item[i]])
            except KeyError as e:
                continue


    return

def parseShodanSearch(ipList):
    '''
    :param ipList: List of IPs received from the uiser
    :return: short (ip port portocol) and long results (everything)
    '''
    # for all IPs in the result
    for ip in ipList:

        print "For IP: " + str(ip) + ""
        results[ip] = {}
        shortResults[ip] = {}
        port = []
        protocol = []
        rest = []

        try:
            # for all data per IP
            for i in ipList[ip]['data']:

                # For all data in "data" variable
                tmpPro = ""
                tmpPort = ""
                for j in i:

                    # get the protocol
                    if str(j) == "_shodan":
                        tmpPro = "(" + str(i[j]['module']) + ")"
                        protocol.append(str(i[j]['module']))
                    if str(j) == "port":
                        tmpPort = "- " + str(i[j]) + " "
                        port.append(str(i[j]))
                    #print str(j)+ " AND " + str(i[j])
                    rest.append({str(j):str([i[j]])})
                print tmpPort+tmpPro
            # store results for short version (ip, port, protocol) or full listing of data in Shodan
            shortResults[ip] = {'port':port,'protocol':protocol}
            results[ip] = {'all':rest}

        # no port for a specific IP
        except TypeError as e:
            print "- No port found"
            print "--------- NEXT IP ---------"
            continue
        print "--------- NEXT IP ---------"

    return {'short':shortResults,'full':results}

if __name__ == '__main__':
    # config TODO: config.ini to read shodan key from
    SHODAN_API_KEY = "YOURKEY"
    api = shodan.Shodan(SHODAN_API_KEY)
    outputFile = "results.csv"
    shortOutputFile = "shortResults"

    if SHODAN_API_KEY == "YOURKEY":
        print "Please edit shoscan.py and replace 'SHODAN_API_KEY' with your real key value"
        quit()

    # arg parse
    parser = argparse.ArgumentParser(description='Port scanning through Shodan.io')
    parser.add_argument('--filename', '-f', default='iplist.txt',required=True)
    parser.add_argument('--fileout', '-o', default=outputFile)
    args = parser.parse_args()

    # read ips from file
    with open(args.filename, 'r') as f:
        ips = [line.strip() for line in f]

    # output info
    art = """
   ,-,--.  ,--.-,,-,--,   _,.---._      ,-,--.    _,.----.    ,---.      .-._         
 ,-.'-  _\/==/  /|=|  | ,-.' , -  `.  ,-.'-  _\ .' .' -   \ .--.'  \    /==/ \  .-._  
/==/_ ,_.'|==|_ ||=|, |/==/_,  ,  - \/==/_ ,_.'/==/  ,  ,-' \==\-/\ \   |==|, \/ /, / 
\==\  \   |==| ,|/=| _|==|   .=.     \==\  \   |==|-   |  . /==/-|_\ |  |==|-  \|  |  
 \==\ -\  |==|- `-' _ |==|_ : ;=:  - |\==\ -\  |==|_   `-' \\==\,   - \ |==| ,  | -|  
 _\==\ ,\ |==|  _     |==| , '='     |_\==\ ,\ |==|   _  , |/==/ -   ,| |==| -   _ |  
/==/\/ _ ||==|   .-. ,\\==\ -    ,_ //==/\/ _ |\==\.       /==/-  /\ - \|==|  /\ , |  
\==\ - , //==/, //=/  | '.='. -   .' \==\ - , / `-.`.___.-'\==\ _.\=\.-'/==/, | |- |  
 `--`---' `--`-' `-`--`   `--`--''    `--`---'              `--`        `--`./  `--` 
                                                              by PathetiQ - 2019/03 
    """
    print art
    print "------------------------------------------"
    print "Using input file: " + args.filename
    print "Output file - all Shodan's details: " + args.fileout
    print "Output file - short version (ip,port,protocol): " + shortOutputFile+"."+args.fileout
    print "------------------------------------------\n"
    print "Launching search..."
    print "Results will be displayed after search is completed..."


    # Search shodan for each IPs
    ipInfo = {}
    for ip in ips:
        time.sleep(1) # Forced Shodan threshold
        try:
            hostinfo = api.host(ip)
            ipInfo[ip] = hostinfo
        except shodan.APIError, e:
            ipInfo[ip] = '{}'.format(e)

    # format the data
    d = json.dumps(ipInfo)
    ipList = json.loads(d)
    shortResults = {}
    results = {}

    # parse the data
    res = parseShodanSearch(ipList)
    # write it out in csv
    writeResults(res,args.fileout,shortOutputFile)

    quit()

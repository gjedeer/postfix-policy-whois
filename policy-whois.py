#!/usr/bin/env python

"""
Postfix policy for querying sender WHOIS entry

Port of https://github.com/purcell/postfix-policy-whois/ for these who don't think
gems are easy for an administrator to deal with

Large parts stolen from pypolicyd-spf source code

in master.cf:
whois     unix  -       n       n       -       1       spawn user=nobody argv=/policy-whois/policy-whois.py

in main.cf:
smtpd_recipient_restrictions =
    reject_unauth_destination
    check_policy_service unix:private/whois

By default: blocks just created and just deleted domains, and freshmail.pl spinoff 
domains which happen to have a correct administrative contact filled out

Dedicated to Freshmail, whose countless emails made me interested in antispam technology.

GPLv3
"""

import os
import re
import sys
import syslog
import whois

debugLevel = 0
data = {}

syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID, syslog.LOG_MAIL)

WHOIS_BLACKLIST = (
    (re.compile('EXPIRED - PENDING DELETE', re.IGNORECASE), 'Domain pending delete'),
    (re.compile('ADDPERIOD', re.IGNORECASE), 'Domain just created'),
    (re.compile('freshmail.pl', re.IGNORECASE), 'Freshmail spam domain'),
)

def check_data(data):
    if 'sender' not in data:
        return ('accept', 'No sender provided')
    sender = data['sender']
    m = re.match(r'.*@(.*)$', sender)
    hostname = m.group(1)
    if hostname.count('.') > 1:
        m = re.search(r'([^\.]+\.[^\.]+)$', hostname)
        domain = m.group(1)
    elif hostname.count('.') == 1:
        domain = hostname
    else:
        return('accept', 'No dots in hostname')
    if debugLevel>=3:syslog.syslog('Sender: %s' % data['sender'])
    if debugLevel>=3:syslog.syslog('Sender domain:%s' % m.group(1))
    whois_client = whois.NICClient()
    who = whois_client.whois_lookup({}, domain, 0)
    if debugLevel >= 4:
        for line in who.splitlines():
            syslog.syslog(line)


    return ('accept', 'Why the hell not')


try:
    lineRx = re.compile(r'^\s*([^=\s]+)\s*=(.*)$')
    while 1:
        line = sys.stdin.readline()
        if not line: break
        line = line.rstrip()
        if debugLevel >= 4: syslog.syslog('Read line: "%s"' % line)

        #  end of entry  {{{2
        if not line:
            if debugLevel >= 4: syslog.syslog('Found the end of entry')

            checkerValue, checkerReason = check_data(data)
    
            #  handle results  {{{3
            if debugLevel >= 3: syslog.syslog('Action: {0}: Text: {1}'.format(checkerValue, checkerReason))
            if checkerValue == 'reject':
                sys.stdout.write('action=550 %s\n\n' % checkerReason)
                
            elif checkerValue == 'prepend':
                if configData.get('Prospective'):
                    sys.stdout.write('action=dunno\n\n')
                else:
                    sys.stdout.write('action=prepend %s\n\n' % checkerReason)

            elif checkerValue == 'defer':
                sys.stdout.write('action=defer_if_permit %s\n\n' % checkerReason)

            elif checkerValue == 'warn':
                sys.stdout.write('action=warn %s\n\n' % checkerReason)

            elif checkerValue == 'result_only':
                sys.stdout.write('action=%s\n\n' % checkerReason)
            else:
                sys.stdout.write('action=dunno\n\n')

            #  end of record  {{{3
            sys.stdout.flush()
            data = {}
            continue

        #  parse line  {{{2
        m = lineRx.match(line)
        if not m:
            syslog.syslog('ERROR: Could not match line "%s"' % line)
            continue

        #  save the string  {{{2
        key = m.group(1)
        value = m.group(2)
        if key not in [ 'protocol_state', 'protocol_name', 'queue_id' ]:
            value = value.lower()
        data[key] = value

    if debugLevel >= 3: syslog.syslog('Normal exit')
except Exception, e:
    import traceback
    for line in traceback.format_exc().splitlines():
        syslog.syslog(line)

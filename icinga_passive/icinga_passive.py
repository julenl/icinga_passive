#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2020, Julen Larrucea <code@larrucea.eu>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GPLv2, the GNU General Public License version 2, as
# published by the Free Software Foundation. http://gnu.org/licenses/gpl.html

"""
This tool executes a command from the shell and send the output as a
"passive" check for the given host and service into the Icinga2 API.
It is written as a poligloth, so it should work in both Python2 and Python3.
It is written in a slightly trickier way to use only modules in the standard
python library.
"""

import os
import ssl
import sys
import json
import socket
import base64
import platform
import subprocess

# Import the functions with the same name to be able to use them
# regardles of the python version
python_version = platform.python_version().split('.')[0]
if python_version == '3':
    from urllib.request import Request, urlopen
elif python_version == '2':
    from urllib2 import Request, urlopen
else:
    print('ERROR: The current Python version is not supported.')
    print('It is neither 2 nor 3!')
    sys.exit(1)


# Do not verify SSL context (probably Icinga2 has a self-signed certificate)
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and 
  getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context


#debug = True
#if debug:
#    import logging
#    try:
#       import http.client as http_client
#    except ImportError:
#        # Python 2
#        import httplib as http_client
#    http_client.HTTPConnection.debuglevel = 1
#    
#    # You must initialize logging, otherwise you'll not see debug output.
#    logging.basicConfig()
#    logging.getLogger().setLevel(logging.DEBUG)
#    requests_log = logging.getLogger("requests.packages.urllib3")
#    requests_log.setLevel(logging.DEBUG)
#    requests_log.propagate = True


try:
    from lib_presets import get_presets
    presets_loaded = True
except Exception as e:
    print("WARNING: Unable to load presets")
    presets_loaded = False


# Create an ssl context to ignore SSL validation
def ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


hostname = socket.gethostname()
# We probably just want the short hostname instead of the FQDN
hostname = hostname.split('.')[0]


# Try to read API credentials from .icinga_api_creds or prompt the user
def load_creds():
    filename = os.path.expanduser('~') + '/.icinga_api_creds'
    if os.path.isfile(filename):
        try:
            with open(filename) as fh:
                creds = json.load(fh)
                if creds:
                    return creds
        except ValueError as e:
            print('ERROR: the "' + filename + '" seems to be empty or have ' +
                  'wrong format')
            sys.exit(1)

    print('Enter the API endpoint for Icinga2, for example:')
    print('  "https://icinga2.example.com:5665"')
    endpoint = input('Icinga2 endpoint: ')
    user = input('Enter the username for the Icinga2 API: ')
    password = input('Enter the password for the Icinga2 API: ')
    if user and password:
        creds = {'username': user,
                 'password': password,
                 'endpoint': endpoint}
        with open(filename, 'w') as fh:
            json.dump(creds, fh)
        return creds


creds = load_creds()
username = creds['username']
password = creds['password']
endpoint = creds['endpoint']

# Python3 requires the auth pair to be in bytes and python2 as string
auth_pair = username + ':' + password
if python_version == '3':
    auth_pair = str.encode(auth_pair)
auth = base64.b64encode(auth_pair)
if python_version == '3':
    auth = auth.decode('utf-8')

# Run a (shell) command and return stdout (list of lines) and RC as a dict
# cmd is a string or a list of elements
def run_cmd(cmd, verbose=False):
    result = {}
    # if isinstance(cmd, str):
    #    cmd = cmd.split()

    if verbose:
        print("Running the following command: " + cmd)
    try:
        out = subprocess.check_output(cmd,
                                      stderr=subprocess.STDOUT,
                                      shell=True
                                      ).decode('utf-8')

        result['rc'] = 0
        result['stdout'] = out.strip()
    except subprocess.CalledProcessError as e:
        result['rc'] = e.returncode
        output = e.output.decode('utf-8')
        result['stdout'] = output.strip()
        print('ERROR: The command exited with status ' + str(result['rc']) +
              'and erro message:')
        print(output)
        sys.exit(1)

    return result
# cmd = 'ls -l'
# cmd = "df |grep '/$' | awk '{print $3}'"
# print(run_cmd(cmd))
# sys.exit(0)


# Build a dictionary to send to the Icinga2 API
# hostname and service_name must be configured already in Icinga2
# the command is an arbitrary command to execture in the current system
# warn and crit is warning and critical threshold
def build_data(hostname, service, command, uom='', warn='', crit=''):
    data = {}
    sservice = service.replace(' ', '_')
    data['type'] = 'Service'
    data['filter'] = 'host.name=="' + hostname + '" && service.name=="'
    data['filter'] += service + '"'
    data['check_source'] = hostname

    # If no command given, we are probably testing the setup
    if not command:
        data['exit_status'] = 0
        data['plugin_output'] = '[OK] It worked'
        return data

    res = run_cmd(command)

    # If the command name starts with "check_" assume we are using some icinga
    # icinga plugin, so the stdout is probably alredy properly formatted and 
    # ready to be sent
    if os.path.basename(command).startswith('check_'):
        data['exit_status'] = res['rc']
        stdout = res['stdout']
        data['plugin_output'] = stdout.split('|')[0]
        if '|' in stdout:
            data['performance_data'] = stdout.split('|')[1]

    else:    
        # If the command exited with error do not go any further
        if res['rc'] != 0:
            data['exit_status'] = 3
            data['plugin_output'] = '[UNKNOWN] Command exited with error'
            return data

        # For arbitrary commands we assume an int or float as output
        try:
            fldig = float(res['stdout'])
            if int(fldig) / fldig == 1:
                stdout = int(fldig)
            else:
                stdout = fldig
        except ValueError as e:
            msg = 'UNKNOWN: Unable to convert "' + str(res['stdout'][0])
            msg += '" to a number'
            data['exit_status'] = 3
            data['plugin_output'] = msg
            return data

        if crit and stdout > crit:
            msg = '[CRITICAL] The value of "' + service + '" is too high | '
            msg += sservice + '=' + str(stdout) + str(uom)
            data['exit_status'] = 2
            data['plugin_output'] = msg
        elif warn and stdout > warn:
            msg = '[WARNING] The value of "' + service + '" is too high | '
            msg += sservice + '=' + str(stdout) + str(uom)
            data['exit_status'] = 1
            data['plugin_output'] = msg
        else:
            msg = sservice + ' [OK] - ' + service + ': ' + str(stdout) 
            data['exit_status'] = 0
            data['plugin_output'] = msg
            msg = "'" + sservice + "'=" + str(stdout) + uom
            msg += ';' + warn + ';' + crit +';;'
            data['performance_data'] = msg 

    return data


# Parse the API username and permissions from the HTML response
def parse_perms(html):
    user = html.split('<b>')[1].split('</b>')[0]
    perm = html.split('<ul>')[1].split('</ul>')[0].split('<li>')
    perm = [ p.replace('</li>', '') for p in perm if p ]
    if username:
        return {'username': user, 'permissions': perm}


# Make an API request to the given path
# If data (dict) is provided, it will be a POST request
def api_req(api_path, data=None, verbose=False):
    # Escape posible spaces or '!' characters in the api_path and GET variables
    if ' ' in api_path:
        api_path = api_path.replace(' ', '%20')
    if '!' in api_path:
        api_path = api_path.replace('!', '%21')
    req_url = endpoint + api_path

    if data:
        data = json.dumps(data)
        # In Python3 the data has to be of type "bytes"
        if python_version == '3':
            data = data.encode('utf-8')

    r = Request(url = req_url, data=data)

    r.add_header("Authorization", "Basic %s" % auth)  
    if data:
        r.add_header("Content-Type", "application/json")  
        r.add_header("Accept", "application/json")  

    if verbose:
        print('Sending the following request:')
        print('URL: ' + req_url)
        print('HTTP-Headers: ' + json.dumps(r.headers, indent=4))
        if data:
            print('Data: ', r.data)

    result = urlopen(r)
    res = result.read()
    if type(res) == bytes:
        res = res.decode('utf-8')

    if verbose:
        print('Result received')

    # If something went wrong or unexpected, tell me more
    try:
        rdict = json.loads(res)
    except ValueError as e:
        data = parse_perms(res)
        if data:
            return data

    if 'results' in rdict and rdict['results']:
        return rdict['results']
    elif 'status' in rdict and rdict['status'] == 'No objects found.':
        print('\nERROR: no objects found on path:')
        print(api_path)
        return []
    else:
        print('\nERROR: something went wrong at API path:')
        print(api_path)
        print('Error message:', rdict)
        sys.exit(1)    


# Take a full permission string and return a list of (broader) permissions
# which would allow that same task
# example: actions/process-check-result' =>
# ['actions/process-check-result', 'actions/*', '*']
def propagate_perm(perm):
    tmp = [perm]
    while perm:
        perm = '/'.join(perm.strip('/*').split('/')[:-1])
        tmp.append(perm + '/*')
    return tmp
# print(propagate_perm('objects/query/Host'))


def run_test(hostname, service, data, verbose=False):
    # print('Check user permissions at the Icinga2 API:', end=' ')
    print('Check user permissions at the Icinga2 API:')
    # req_permissions = ['actions/process-check-result', 'actions/*', '*']
    res = api_req('/v1', verbose=verbose)
    if 'username' in res and 'permissions' in res and res['permissions']:
        user, perm = res['username'], res['permissions']
    else:
        print('ERROR: Something went wrong when authenticating,')
        print(' or the user has no permissions')
        sys.exit(1)

    pp = propagate_perm('actions/process-check-result')
    if any(item in perm for item in pp):
        print('OK')
    else:
        print('ERROR: the user "' + user + '" does not have enough ' +
              'permissions to run passive checks:')
        print('  ' + ','.join(perm))
        sys.exit(1)

    pp = propagate_perm('objects/query/Host')
    if any(item in perm for item in pp):
        # print('Check if host "' + hostname + '" exists in Icinga:', end=' ')
        print('Check if host "' + hostname + '" exists in Icinga2:')
        req_url = '/v1/objects/hosts?hosts=' + hostname + ''
        res = api_req(req_url, verbose=verbose)
        if res:
            print('OK')
        else:
            print('\n ERROR: the host "' + hostname + '" is not defined ' +
                  'in Icinga2.')
    else:
        print('  Not enough permissions to ask whether the host "' +
              hostname + '" exists in Icinga2.')

    pp = propagate_perm('objects/query/Service')
    if any(item in perm for item in pp):
        # print('Check if the service "' + service + '" exists for "' +
        # hostname + '":', end=' ')
        print('Check if the service "' + service + '" exists for "' +
              hostname + '":')
        req_url = '/v1/objects/services?service=' + hostname + '!'
        req_url += service

        if verbose:
            print("Request URL: " + req_url)

        res = api_req(req_url, verbose=verbose)
        if res:
            print('OK')
        else:
            print('\n ERROR: the service "' + hostname + '!' +
                  service + '" is not defined in Icinga2.')
            req_url = '/v1/objects/services'
            a_srv = api_req(req_url)
            print()
            h_srv = [s for s in a_srv if s['attrs']['host_name'] == hostname]
            p_srv = [s['name'] for s in h_srv if not
                     s['attrs']['last_check_result']['command']]
            print('Available services for host "' + hostname + '":')
            print(' - ' + '- \n'.join(p_srv))
            sys.exit(1)
    else:
        print('  Not enough permissions to ask whether the service "' +
              service + '" exists for the host "' + hostname +
              '" in Icinga2.')


def push_data(data, verbose=False):
    if verbose:
        print('# Sending the following data to the Icinga API:')
        print(json.dumps(data, indent=4))
        print('')
        print('# Message for Icinga2:')
        print(data['plugin_output'])

    api_path = '/v1/actions/process-check-result'
    api_req(api_path, data, verbose)


def main():
    import argparse
    global hostname

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--service', type=str,
                        help='Name of the service, recognised by Icinga2')
    parser.add_argument('--host', type=str, default=hostname.split('.')[0],
                        help='Hostname, recognised by Icinga2 (def. current' +
                             ' host)')
    parser.add_argument('-c', '--command', type=str,
                        help='Command to retrieve the results from')
    parser.add_argument('-u', '--uom', choices=['','s','%','B','c'], default='',
                        help='Unit Of Measurement for Nagios compatible metrics')
    parser.add_argument('--warn', default='',
                        help='Return "Warning" if response is above this '
                             'value')
    parser.add_argument('--crit', default='',
                        help='Return "Critical" if response is above this ' +
                             'value')
    if presets_loaded:
        parser.add_argument('-p', '--preset', type=str,
                            help='Use a preset command instead of writing ' +
                                 'your own')
        parser.add_argument('--list_presets', action='store_true',
                            help='Show the available presets')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print verbose output')
    parser.add_argument('-t', '--test', action='store_true',
                        help='Test to make sure the service is monitored')

    args = parser.parse_args()

    hostname = args.host or socket.gethostname().split('.')[0]

    command = ''
    uom = ''
    if presets_loaded:
        presets = get_presets()
        if args.list_presets:
            for pre in presets.keys():
                print('- ' + pre + ':  ' + presets[pre]['Description'])
                print(' # ' + presets[pre]['Command'])
                print('')
            sys.exit(0)
        elif args.preset:
            if args.verbose:
                print('Using preset command: ' + args.preset)
                print('  ' + presets[args.preset]['Command'])
            command = presets[args.preset]['Command']
            if 'UOM' in presets[args.preset]:
                uom = presets[args.preset]['UOM']
            else:
                uom = ''

    if args.command:
        command = args.command
        uom = args.uom

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)


    if not command and not args.test:
        print('ERROR: A command expression is required with the "-c" or ' +
              '"--command" flag.')
        print('Example: -c "df |grep \'/$\' | awk \'{print $3}\'"')
        print('Alternatively you can provide a preset command with "--preset"')
        print('')
        parser.print_help()
        sys.exit(1)

    if not args.service:
        print('ERROR: You must provide a service')
        sys.exit(1)

    data = build_data(
                      hostname=hostname,
                      service=args.service,
                      command=command,
                      uom=uom,
                      warn=args.warn,
                      crit=args.crit
                      )

    if args.test:
        run_test(hostname, args.service, data, verbose= args.verbose)
        sys.exit(0)

    push_data(data=data, verbose=args.verbose)


if __name__ == '__main__':
    main()

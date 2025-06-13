#!/usr/bin/env python3

import vt  # https://github.com/VirusTotal/vt-py
import time
from datetime import datetime
import sys
import os
import argparse
import ast 

available_requests = 500
config_path = './.vtipPy.conf'

# probably useless, consider getting rid*************************************************************************
def check_args():
    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        print('# ERROR')
        print('# Please specify a file of IP addresses to check. File should contain one IP address per line.')
        print('# Use syntax:')
        print('# \tpython3 vtipPy.py /path/to/file.txt')
        exit(1)

def get_time():
    # returns a datetime.now() but formatted yyyy-mm-dd hh:mm:ss
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def update_config(config):
    config[f'conf_updated_time'] = get_time()
    config_string = ''
    for key in config:
        config_string += f'{key}={config[key]}\n'
    
    config_string = config_string[:-1]  # remove trailing \n

    with open(config_path, 'wt') as file:
        file.write(config_string)

def cast_value(value):
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value.strip('"').strip("'")

def get_config():
    config = {}

    if os.path.isfile(config_path):
        print(f'# Reading config at {config_path}...')
        with open(config_path, 'rt') as file:
            config_list = file.read().strip().split('\n')

        for item in config_list:
            if '=' in item:
                key, value = item.split('=', 1)
                config[key] = cast_value(value)

    else:
        print(f'# Writing config at {config_path}...')
        config['api_key'] = ''
        config['requests_started_at'] = f'{get_time()}'
        config['available_requests'] = 500
        config['voted_malicious'] = []
        config['detected_malicious'] = []
        config['detected_suspicious'] = []
        update_config(config)

    return config

def get_available_requests(config):
    requests_started_at = datetime.strptime(config['requests_started_at'], "%Y-%m-%d %H:%M:%S")
    time_since_first_request = requests_started_at - datetime.now()

    if time_since_first_request.total_seconds() > 86400:
        print('# It\'s been more than 24 hours since API usage last began: Resetting available requests to 500')
        config['available_requests'] = 500
    
    return config

def parse_arguments():
    parser = argparse.ArgumentParser(
        prog='vtipPy',
        description=(
            "Easily check IP addresses against VirusTotal's public API\n"
            "Config is saved at     if args.resume:"
        ),
        epilog=(
            "Usage:\n"
            "  vtipPy.py -f /path/to/input/file\n"
            "  vtipPy.py --resume -f /path/to/input/file"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-f', '--file',
        help='Specify an input file',
        action='store', 
        required=True
        )

    parser.add_argument(
        '-o', '--output',
        help='Specify a name for an output file',
        action='store'
        )

    parser.add_argument(
        '-r', '--resume',
        help='Resume a scan from a previous day',
        action='store_true'
        )
    
    parser.add_argument(
        '-F', '--force',
        help='Skip confirmations for overwrites, etc.',
        action='store_true'
        )

    parser.add_argument(
        '-q', '--quiet',
        help='Supress most output (excluding confirmation)',
        action='store_true'
        )


    args = parser.parse_args()

    # Set default output filename if not provided
    if args.output is None:
        base, _ = os.path.splitext(os.path.basename(args.file))
        args.output = f"{base}_out.txt"

    return args


# need to add:
#   -resume functionality
#       -so like, some way to save the number of requests already made in the config file
#       -and a way to read it and start scanning again from that number
#   -etc. idk.


def main():
    global available_requests

    args = parse_arguments()
    config = get_config()
    config = get_available_requests(config)
    if config['api_key'] == '':
        print('# To start checking IPs against the VirusTotal API, you need to provide your VirusTotal API key.')
        print('# If you don\'t know how to get one, start here: https://docs.virustotal.com/docs/please-give-me-an-api-key')
        print()
        print('# After you input your API key once per project directory, it will remain saved in ./.vtipPy.conf')
        api_key = input('# Paste your API key here: ')
        config['api_key'] = api_key


    available_requests = int(config['available_requests'])
    print(f'# You have {available_requests} requests remaining until tomorrow')

    with open(f'{args.file}', "rt") as file:
        ips = file.read()

    '''
    print('EXITING DUE TO TESTING')
    exit()
    '''


    ips = ips.split('\n')
    
    print(f'# Input file contains {len(ips)} lines.')
    if len(ips) > 500:
        print('# Due to the daily limit of requests on the public VirusTotal API, your job won\'t be able to finish today.')
        print('# Run the program again tomorrow with the following syntax:')
        print('#\t python3 vtipPy.py --resume /path/to/IP_FILE')


    # if the user does not include -r
    if not args.resume:

        # but there is resume data available
        if f'checked_in_{args.file}' in config and not args.force:
            print(f'# WARNING: You are about to start a scan over for {args.file} even though the scan may be able to be resumed.')
            print(f'# To resume the previous scan, answer NO and rerun the command with -r')
            print(f'# Starting the scan over will overwrite any existing output files from the previous scan.')
            choice = input(f'# Would you like to start the scan over? Y/N')

            if choice == 'y' or choice == 'Y' or choice == 'yes' or choice == 'YES' or choice == 'Yes':
                print('# Okay, starting scan over from scratch...')
                config[f'checked_in_{args.file}'] = 0
                if os.path.isfile(args.output):
                    open(args.output, 'w').close()  # wipe the old output
            else:
                print('# Okay, exiting...')
                exit()

        # and there is not resume data available
        else:
            config[f'checked_in_{args.file}'] = 0

    # elif the user includes -r and the resume data is available
    elif args.resume and f'checked_in_{args.file}' in config:
        print(f'# Resuming scan starting from IP address #{config[f"checked_in_{args.file}"]} in {args.file}')

        # remove the IPs that have already been scanned
        ips = ips[int(config[f'checked_in_{args.file}']) + 1:]
    
    # if user includes -r but there is no resume data available.
    elif args.resume and f'checked_in_{args.file}' not in config:
        print(f'# WARNING: There is no resume data for {args.file} in the configuration file.')
        print(f'# Exiting...')
    
    # update the config with the new resume/checked_in values
    update_config(config)

    if f"checked_in_{args.file}" in config:
        ips_already_checked = int(config[f"checked_in_{args.file}"])
    else:
        config[f"checked_in_{args.file}"]  = 0
        ips_already_checked = 0

    for line in ips:
        if available_requests < 1:
            print('# Daily Limit reached. You can start again tomorrow by adding -r to the same command')
            print('# Your place will be saved in the config.')
            print('# Exiting...')
            exit()
            break

        try:
            try:
                int_check=int(line[0].split('.')[0])
            except:
                print(f'"{line}" is not an int, skipping line...')
                continue

            ip_to_check=line

            with vt.Client(config['api_key']) as client:
                IP = client.get_object(f"/ip_addresses/{ip_to_check}")
                available_requests-=1

                output_to_write = f'{ip_to_check}, {IP.total_votes}, {IP.last_analysis_stats}\n'
                if not args.quiet:
                    print(output_to_write)
                with open(args.output, 'a') as file:
                    file.write(output_to_write)
            
            # check community sentiment & store for summary
            if IP.total_votes['malicious'] > 0:
                config['voted_malicious'].append(ip_to_check)
            
            # check AV detection & store for summary
            if IP.last_analysis_stats['malicious'] > 0:
                print('det mal')
                list(config['detected_malicious']).append(ip_to_check)
            
            if IP.last_analysis_stats['suspicious'] > 0:
                print('det sus')
                list(config['detected_suspicious']).append(ip_to_check)

            # update resume counter and config
            config['available_requests'] = available_requests
            ips_already_checked += 1
            config[f'checked_in_{args.file}'] = ips_already_checked
            update_config(config)

        except Exception as e:
            print(f"Error: {e}")
        except:
            error_string=f'Something strange happened. Line was: {line}\n'
            out_file_errors = open('vt_ip_errors.txt', 'a')
            out_file_errors.write(error_string)
            out_file_errors.close()
            print(error_string)
            break

        time.sleep(15)    # sleep to maintain 4 requests/minute (public API ratelimit)


if __name__ == '__main__':
    main()
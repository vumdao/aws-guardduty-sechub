import requests
from datetime import datetime
import json
import os


webhook_url = os.getenv('WEBHOOK_URL')
footer_icon = 'https://howtofightnow.com/wp-content/uploads/2018/11/cartoon-firewall-hi.png'
color = '#E01E5A'
level = ':boom: ALERT :boom:'
curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
console_url = 'https://console.aws.amazon.com/securityhub'


def send_msg_slack(region, message):
    payload = {"username": "SecurityHub",
               "attachments": [{"pretext": level,
                                "color": color,
                                "text": f"AWS SecurityHub finding in {region}: {message}",
                                "footer": f"{curr_time}",
                                "footer_icon": footer_icon}]}
    requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

def send_ip_slack(region, messageId, state=True):
    """ Send payload to slack """
    if state:
        message = f"Finding New IP\nSucceed to block IP: {messageId}"
    else:
        message = f'Finding New IP\nFailed to block IP: {messageId}'
    fallback = f"finding - {console_url}/home?region={region}#/findings?search=id%3D${messageId}"
    payload = {"username": "SecurityHub",
               "attachments": [{"fallback": fallback,
                                "pretext": level,
                                "color": color,
                                "text": f"AWS SecurityHub finding in {region}: {message}",
                                "footer": f"{curr_time}\n{fallback}",
                                "footer_icon": footer_icon}]}
    requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})


def send_finding_slack(region, f_id, msg):
    """ Send payload to slack """
    fallback = f"finding - {console_url}/home?region={region}#/findings?search=id%3D${f_id}"
    payload = {"username": "SecurityHub",
               "attachments": [{"fallback": fallback,
                                "pretext": level,
                                "color": color,
                                "text": f"AWS SecurityHub finding in {region} {msg}",
                                "footer": f"{curr_time}\n{fallback}",
                                "footer_icon": footer_icon}]}
    requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})


def handler(event, context):
    if 'Message' in event and 'HostIp' in event['Message']:
        """ Block IPs status """
        message_id = event['Message']['HostIp']
        region = event['Message']['Region']
        if event['Message']['Blocked'] == "true":
            send_ip_slack(region, message_id)
        else:
            send_ip_slack(region, message_id, state=False)
    elif 'Message' in event:
        """ Other notifications """
        message = event['Message']['Message']
        region = event['Message']['Region']
        send_msg_slack(region, message)
    else:
        region = event['Region']
        finding_id = event['Finding_ID']
        finding_desc = event['Finding_description']
        severity = event['severity']
        finding_type = event['Finding_Type']
        msg = f"Finding new detection: severity {severity}, type: {finding_type} - {finding_desc}"
        send_finding_slack(region, finding_id, msg)
    return {"Status": "Ok"}

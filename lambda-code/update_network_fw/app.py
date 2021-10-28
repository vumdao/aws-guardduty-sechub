import os, json, logging
import boto3


logger = logging.getLogger()
logger.setLevel(logging.INFO)


RuleGroupArn = os.environ['FIREWALLRULEGROUP']
RuleGroupPriority = os.environ['RULEGROUPPRI']
CustomActionName =  os.environ['CUSTOMACTIONNAME']
CustomActionValue =  os.environ['CUSTOMACTIONVALUE']


def create_sources(block_list):
    response = []
    for i in block_list:
        response.append({'AddressDefinition': str(i['IP']) + '/32' })
    return response


def get_rg_config():
    client = boto3.client('network-firewall')
    response = client.describe_rule_group(
        RuleGroupArn=RuleGroupArn,
        Type='STATELESS'
    )
    return response


def update_rg_config(block_list):
    client = boto3.client('network-firewall')
    currgconfig = get_rg_config()
    RuleGroupPriorityDst = int(RuleGroupPriority) + 100

    #Create new rule from dictionary of IPs CIDRS to block
    newrules = [
        {
            'RuleDefinition': {
                'MatchAttributes': {
                    'Sources': create_sources(block_list)
                },
                'Actions': [
                    'aws:drop',
                    CustomActionName
                ]
            },
            'Priority': int(RuleGroupPriority)
        },
        {
            'RuleDefinition': {
                'MatchAttributes': {
                    'Destinations': create_sources(block_list)
                },
                'Actions': [
                    'aws:drop',
                    CustomActionName
                ]
            },
            'Priority': int(RuleGroupPriorityDst)
        }
    ]

    # Custom Actions provide CloudWatch metrics
    customactions = [
        {
            'ActionName': CustomActionName,
            'ActionDefinition': {
                'PublishMetricAction': {
                    'Dimensions': [
                        {
                            'Value': CustomActionValue
                        }
                    ]
                }
            }
        }
    ]

    # Preserve current rules not used here in rule group by appending to new rule
    newrgconfig = currgconfig['RuleGroup']['RulesSource']['StatelessRulesAndCustomActions']['StatelessRules']
    try:
        for r in newrgconfig:
            if int(r['Priority']) not in [ int(RuleGroupPriority), int(RuleGroupPriorityDst) ]:
                newrules.append(r)

        #Update the rule group
        logger.info("Update Rule Group ARN, %s." % RuleGroupArn)
        response = client.update_rule_group(
            UpdateToken=currgconfig['UpdateToken'],
            RuleGroupArn=RuleGroupArn,
            RuleGroup={
                'RulesSource': {
                    'StatelessRulesAndCustomActions': {
                        'StatelessRules':
                            newrules,
                        'CustomActions':
                            customactions
                    }
                }
            },
            Type='STATELESS',
            Description='GD2NFW',
            DryRun=False
        )
    except Exception as e:
        logger.error(f'something went wrong, error {e}')
        raise


def handler(event, context):
    logger.info("log -- Event: %s " % json.dumps(event))

    # retrieve a list of IPs delivered from the previous step in the State Machine
    block_list = event['IPList']

    # if empty, provide a fake entry - rule group update requires at least one entry
    if len(block_list) == 0:
      block_list = [{'IP':'127.0.0.1'}]

    # update the AWS Network Firewall Rule Group
    # replace with the updated list of IPs
    update_rg_config(block_list)

    # check if the function was called for blocking or pruning
    if ('HostIp' in event):
        # blocking completed, pass the data on to the next step
        return {
            "HostIp": event['HostIp'],
            "FindingId": event['FindingId'],
            "Timestamp": event['Timestamp'],
            "AccountId": event['AccountId'],
            "Region": event['Region']
        }
    else:
        # this was a pruning action
        return {
          "PruningSuccessful": True
        }
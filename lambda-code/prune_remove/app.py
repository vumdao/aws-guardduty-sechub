import os, boto3, logging, json


logger = logging.getLogger()
logger.setLevel(logging.INFO)


ACLMETATABLE = os.environ['ACLMETATABLE']
ddb = boto3.resource('dynamodb')
table = ddb.Table(ACLMETATABLE)


def Delete_DynamoDB_Items(IPList):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    for IP in IPList:
        response = table.delete_item(
            Key={
                'HostIp': IP['IP']
                }
            )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('log -- Delete_DynamoDB_Item successful')
            return True
        else:
            logger.error('log -- Delete_DynamoDB_Item FAILED')
            logger.info(response['ResponseMetadata'])


def getAllIPs():
    """ Gets all IPs in the DynamoDB table """
    IPList = []
    try:
        #scan the ddb table to find expired records
        response = table.scan()
        # if any records are found:
        if response['Items']:
            logger.info("log -- found records")
            # process each expired record, append to list
            for item in response['Items']:
                logger.info("HostIp %s" %item['HostIp'])
                IPList.append({"IP": item['HostIp']})
        else:
            logger.info("log -- no entries found.")
    except Exception as e:
        logger.error('something went wrong')
        raise
    # respond with a list of all IPs in DynamoDB table
    return IPList


def handler(event, context):
    logger.info("log -- Event: %s " % json.dumps(event))
    # get the IP address to be removed from DynamoDB
    IPList = event['ExpiredIPList']
    logger.info("log -- removing IP addresses %s" % IPList)
    # delete expired IPs
    Delete_DynamoDB_Items(IPList)
    # retrieve IP addresses that need to be still in the rule group
    json_response = {}
    json_response['IPList'] = getAllIPs()
    return json_response
import os, boto3, logging, json, time
from boto3.dynamodb.conditions import Attr


logger = logging.getLogger()
logger.setLevel(logging.INFO)


ACLMETATABLE = os.environ['ACLMETATABLE']
RETENTION = os.environ['RETENTION']
ddb = boto3.resource('dynamodb')
table = ddb.Table(ACLMETATABLE)


def getExpiredIPs(expire_time):
    """ Scan the ddb table to find expired records and then return nested JSON with a list of IPs """
    Return_JSON = {}
    ExpiredIPList = []
    try:
        response = table.scan(FilterExpression=Attr('CreatedAt').lt(expire_time))
        if response['Items']:
            logger.info("log -- found expired entries, %s." % (response)['Items'])
            Return_JSON['PruningNeeded'] = True
            for item in response['Items']:
                logger.info("HostIp %s" %item['HostIp'])
                ExpiredIPList.append({"IP": item['HostIp']})
        else:
            logger.info("log -- no entries older than %s minutes found." % (int(RETENTION)))
            Return_JSON['PruningNeeded'] = False
    except Exception as e:
        logger.error('something went wrong')
        raise

    Return_JSON['ExpiredIPList'] = ExpiredIPList
    return Return_JSON


def handler(event, context):
  logger.info("log -- Event: %s " % json.dumps(event))
  # records older than this time stamp should be pruned
  expire_time = int(time.time()) - (int(RETENTION)*60)
  logger.info("log -- expire_time = %s" % expire_time)
  response = getExpiredIPs(expire_time)
  return response
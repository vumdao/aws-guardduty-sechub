import * as pulumi from '@pulumi/pulumi';
import * as aws from '@pulumi/aws';
import { region } from './config';


export const guardduty_firewall_ddb = new aws.dynamodb.Table('guardduty_firewall_ddb', {
    name: `${region}-gd-firewall`,
    billingMode: 'PAY_PER_REQUEST',
    attributes: [{
        name: 'HostIp',
        type: 'S'
    }],
    hashKey: 'HostIp',
    tags: {
        'Name': `${region}-gd-firewall`,
        'pulumi': 'ddb-stack'
    }
});

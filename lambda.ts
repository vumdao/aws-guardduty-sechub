import * as pulumi from '@pulumi/pulumi';
import * as aws from '@pulumi/aws';
import { region, webhook_url } from './config';
import { guardduty_firewall_ddb } from './ddb';
import { nf_rg } from './nfrg';


const lambda_role = new aws.iam.Role('GuardDutySechubLambdaRole', {
    name: `${region}-gd-sechub-lambda`,
    description: 'Lambda role to read/write DDB',
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Sid: "",
            Principal: {
                Service: "lambda.amazonaws.com",
            },
        }]
    }),
    tags: {
        'Name': `${region}-gd-sechub-lambda`,
        'stack': 'pulumi-iam-role'
    }
});

const lambda_policy = new aws.iam.RolePolicy("allow-rw-ddb", {
    role: lambda_role,
    policy: {
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "AllowDDBStatement",
                Effect: "Allow",
                Resource: guardduty_firewall_ddb.arn,
                Action: [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:Scan"
                ]
            },
            {
                Sid: "AllowKmsStatement",
                Effect: "Allow",
                Resource: 'arn:aws:kms:us-west-2:123456789012:key/6730189c-8d04-5d65-b160-b801152c2cfb',
                Action: "kms:Decrypt",
                "Condition": {
                    "StringEquals": {
                      "kms:EncryptionContext:LambdaFunctionName": "us-west-2-send-gd-finding"
                    }
                }
            },
            {
                Sid: "AllowNetworkFireWallStatement",
                Effect: "Allow",
                Resource: nf_rg.arn,
                Action: [
                    "network-firewall:DescribeRuleGroup",
                    "network-firewall:UpdateRuleGroup"
                ]
            },
            {
                Sid: 'AllowLog',
                Effect: 'Allow',
                Resource: "arn:aws:logs:*:*:*",
                Action: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
            }
        ]
    },
}, {parent: lambda_role});


function createLogGroup(scopeName: string, logGroupName: string): any {
    let lg = new aws.cloudwatch.LogGroup(scopeName, {
        name: `/aws/lambda/${region}-${logGroupName}`,
        retentionInDays: 7,
        tags: {
            'Name': `${region}-${logGroupName}`,
            'stack': 'pulumi-log-group'
        }
    });

    return lg
};

export const add_ip_func = new aws.lambda.Function('AddIPToDDB', {
    name: `${region}-add-ip-to-ddb`,
    description: 'Add suspicious IPs to DDB for blocking',
    runtime: aws.lambda.Runtime.Python3d8,
    code: new pulumi.asset.FileArchive('lambda-code/add_ip/handler.tar.gz'),
    handler: 'app.handler',
    role: lambda_role.arn,
    environment: {
        variables: {
            'ACLMETATABLE': guardduty_firewall_ddb.name
        }
    }
}, {dependsOn: createLogGroup('AddIpLogGroup', 'add-ip-to-ddb')});

export const get_ip_func = new aws.lambda.Function('GetExpiredIPsFromDDB', {
    name: `${region}-get-ip-from-ddb`,
    description: 'Get Expired IPs from DDB',
    runtime: aws.lambda.Runtime.Python3d8,
    code: new pulumi.asset.FileArchive('lambda-code/prune_get/handler.tar.gz'),
    handler: 'app.handler',
    role: lambda_role.arn,
    environment: {
        variables: {
            'ACLMETATABLE': guardduty_firewall_ddb.name,
            'RETENTION': '720'
        }
    }
}, {dependsOn: createLogGroup('GetExpiredIPsFromDDBLogGroup', 'get-ip-from-ddb')});

export const remove_ip_func = new aws.lambda.Function('RemoveExpiredIPsFromDDB', {
    name: `${region}-remove-ip-from-ddb`,
    description: 'Remove Expired IPs from DDB',
    runtime: aws.lambda.Runtime.Python3d8,
    code: new pulumi.asset.FileArchive('lambda-code/prune_remove/handler.tar.gz'),
    handler: 'app.handler',
    role: lambda_role.arn,
    environment: {
        variables: {
            'ACLMETATABLE': guardduty_firewall_ddb.name
        }
    }
}, {dependsOn: createLogGroup('RemoveExpiredIPsFromDDBLogGroup', 'remove-ip-from-ddb')});

export const send_finding_func = new aws.lambda.Function('SendingGuardDutyFindings', {
    name: `${region}-send-gd-finding`,
    description: 'Send GuardDuty Findings to Slack',
    runtime: aws.lambda.Runtime.Python3d8,
    code: new pulumi.asset.FileArchive('lambda-code/send_finding/handler.tar.gz'),
    handler: 'app.handler',
    role: lambda_role.arn,
    environment: {
        variables: {
            'WEBHOOK_URL': webhook_url
        }
    }
}, {dependsOn: createLogGroup('SendingGuardDutyFindingsLogGroup', 'send-gd-finding')});

export const update_rule_group_func = new aws.lambda.Function('UpdateRuleGroup', {
    name: `${region}-update-nf-rg`,
    description: 'Update network firewall rule group',
    runtime: aws.lambda.Runtime.Python3d8,
    code: new pulumi.asset.FileArchive('lambda-code/update_network_fw/handler.tar.gz'),
    handler: 'app.handler',
    environment: {
        variables: {
            'FIREWALLRULEGROUP': nf_rg.arn,
            'RULEGROUPPRI': '30000',
            'CUSTOMACTIONNAME': 'GuardDutytoFirewall',
            'CUSTOMACTIONVALUE': 'GD2NWF-rule-group'
        }
    },
    role: lambda_role.arn
}, {dependsOn: createLogGroup('UpdateRuleGroup', 'update-nf-rg')});
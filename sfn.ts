import * as pulumi from '@pulumi/pulumi';
import * as aws from '@pulumi/aws';
import { region } from './config';
import * as handler from './lambda';


export const sfn_role = new aws.iam.Role('SfnRdsRole', {
    name: `${region}-sechub-sfn`,
    description: 'Role to trigger lambda functions',
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Sid: "",
            Principal: {
                Service: `states.${region}.amazonaws.com`,
            },
        }],
    }),
    tags: {
        'Name': `${region}-sechub-sfn`,
        'stack': 'pulumi-iam-role'
    }
});

let handlers: pulumi.Output<string>[] = [
    handler.add_ip_func.arn,
    handler.get_ip_func.arn,
    handler.remove_ip_func.arn,
    handler.send_finding_func.arn,
    handler.update_rule_group_func.arn
]

const policy = new aws.iam.RolePolicy("allow-invoke-lambda", {
    role: sfn_role,
    name: 'allow-invoke-sfn-lambda',
    policy: {
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "AllowRdsStatement",
                Effect: "Allow",
                Resource: handlers,
                Action: "lambda:InvokeFunction",
            }
        ]
    },
}, {parent: sfn_role});

export const record_ip_sfn = new aws.sfn.StateMachine('RecordIpSfn', {
    name: `${region}-sechub-record-ip`,
    roleArn: sfn_role.arn,
    tags: {
        'Name': `${region}-sechub-record-ip`,
        'stack': 'pulumi-sfn'
    },
    definition: pulumi.all([handler.add_ip_func.arn, handler.send_finding_func.arn, handler.update_rule_group_func.arn])
        .apply(([addIpArn, sendFindingArn, updateNetworkfwArn]) => {
        return JSON.stringify({
            "Comment": "Triggered by GuardDuty finding, checks if remote IP is identified, then blocks traffic to that IP",
            "StartAt": "RecordIpDDBTask",
            "States": {
                "RecordIpDDBTask": {
                    "Type": "Task",
                    "Resource": addIpArn,
                    "Parameters": {
                        "comment": "Relevant fields from the GuardDuty / Security Hub finding",
                        "HostIp.$": "$.detail.findings[0].ProductFields.aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4",
                        "Timestamp.$": "$.detail.findings[0].ProductFields.aws/guardduty/service/eventLastSeen",
                        "FindingId.$": "$.id",
                        "AccountId.$": "$.account",
                        "Region.$": "$.region"
                    },
                    "Retry": [
                        {
                        "ErrorEquals": [
                            "Lambda.Unknown",
                            "States.TaskFailed"
                        ],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 2,
                        "BackoffRate": 2
                        }
                    ],
                    "Catch": [
                        {
                        "ErrorEquals": [
                            "States.ALL"
                        ],
                        "Next": "Notify Failure"
                        }
                    ],
                    "Next": "New IP?"
                },
                "New IP?": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.NewIP",
                            "BooleanEquals": true,
                            "Next": "BlockTraffic"
                        }
                    ],
                    "Default": "No Firewall Change"
                },
                "No Firewall Change": {
                    "Type": "Succeed",
                },
                "BlockTraffic": {
                    "Type": "Task",
                    "Resource": updateNetworkfwArn,
                    "Retry": [
                        {
                            "ErrorEquals": [
                                "States.TaskFailed"
                            ],
                            "IntervalSeconds": 2,
                            "MaxAttempts": 2,
                            "BackoffRate": 2
                        }
                    ],
                    "Catch": [
                        {
                            "ErrorEquals": [
                                "States.ALL"
                            ],
                            "Next": "Notify Failure"
                        }
                    ],
                    "Next": "Notify Success"
                },
                "Notify Success": {
                    "Type": "Task",
                    "Resource": sendFindingArn,
                    "Parameters": {
                        "Message": {
                            "Blocked": "true",
                            "Input.$": "$"
                        }
                    },
                    "End": true
                },
                "Notify Failure": {
                    "Type": "Task",
                    "Resource": sendFindingArn,
                    "Parameters": {
                        "Message": {
                            "Blocked": "false",
                            "Input.$": "$"
                        },
                    },
                    "End": true
                }
            }
        })
    })
});

export const pruning_ip_sfn = new aws.sfn.StateMachine('PruneIpSfn', {
    name: `${region}-sechub-prune-ip`,
    roleArn: sfn_role.arn,
    tags: {
        'Name': `${region}-sechub-prune-ip`,
        'stack': 'pulumi-sfn'
    },
    definition: pulumi.all([handler.get_ip_func.arn, handler.remove_ip_func.arn, handler.send_finding_func.arn, handler.update_rule_group_func.arn])
        .apply(([getIpArn, removeIpArn, sendFindingArn, updateNetworkfwArn]) => {
        return JSON.stringify({
            "Comment": "Triggered by GuardDuty finding, checks if remote IP is identified, then blocks traffic to that IP",
            "StartAt": "Get Expired Records from DynamoDB",
            "States": {
                "Get Expired Records from DynamoDB": {
                    "Type": "Task",
                    "Resource": getIpArn,
                    "Retry": [
                        {
                            "ErrorEquals": [
                                "States.TaskFailed"
                            ],
                            "IntervalSeconds": 2,
                            "MaxAttempts": 2,
                            "BackoffRate": 2
                        }
                    ],
                    "Parameters": {
                        "comment": "Retrieve expired records from the DynamoDB table"
                    },
                    "Catch": [
                        {
                            "ErrorEquals": [
                                "States.ALL"
                            ],
                            "Next": "Notify Failure to Get Expired IPs"
                        }
                    ],
                    "Next": "Is Pruning Needed?"
                },
                "Is Pruning Needed?": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.PruningNeeded",
                            "BooleanEquals": true,
                            "Next": "Remove Records from DynamoDB"
                        }
                    ],
                    "Default": "No Pruning Needed"
                },
                "No Pruning Needed": {
                    "Type": "Succeed",
                },
                "Remove Records from DynamoDB": {
                    "Type": "Task",
                    "Resource": removeIpArn,
                    "Retry": [
                        {
                            "ErrorEquals": [
                                "States.TaskFailed"
                            ],
                            "IntervalSeconds": 2,
                            "MaxAttempts": 2,
                            "BackoffRate": 2
                        }
                    ],
                    "Catch": [
                        {
                            "ErrorEquals": [
                                "States.ALL"
                            ],
                            "Next": "Notify Failure"
                        }
                    ],
                    "Next": "Remove IPs from Firewall"
                },
                "Remove IPs from Firewall": {
                    "Type": "Task",
                    "Resource": updateNetworkfwArn,
                    "Parameters": {
                        "IPList.$": "$.IPList",
                        "comment": "Overwrites the RuleGrop with the updated list with expired IPs removed"
                    },
                    "Retry": [
                        {
                            "ErrorEquals": [
                                "States.TaskFailed"
                            ],
                            "IntervalSeconds": 2,
                            "MaxAttempts": 2,
                            "BackoffRate": 2
                        }
                    ],
                    "Catch": [
                        {
                            "ErrorEquals": [
                                "States.ALL"
                            ],
                            "Next": "Notify Failure"
                        }
                    ],
                    "Next": "Pruning Completed"
                },
                "Pruning Completed": {
                    "Type": "Succeed"
                },
                "Notify Failure": {
                    "Type": "Task",
                    "Resource": sendFindingArn,
                    "Parameters": {
                        "Message": {
                            "Message": "Pruning Failed",
                            "Region": region
                        }
                    },
                    "End": true
                },
                "Notify Failure to Get Expired IPs": {
                    "Type": "Task",
                    "Resource": sendFindingArn,
                    "Parameters": {
                        "Message": {
                            "Message": "Pruning Failed - could not get expired IPs",
                            "Region": region
                        }
                    },
                    "End": true
                }
            }
        })
    })
});

export const high_severity_finding_sfn = new aws.sfn.StateMachine('HighSeverityFindingSnf', {
    name: `${region}-sechub-send-findings`,
    roleArn: sfn_role.arn,
    tags: {
        'Name': `${region}-sechub-send-findings`,
        'stack': 'pulumi-sfn'
    },
    definition: pulumi.all([handler.send_finding_func.arn])
        .apply(([sendFindingArn]) => {
        return JSON.stringify({
            "Comment": "Others fields from the GuardDuty / Security Hub finding",
            "StartAt": "Send findings to slack",
            "States": {
                "Send findings to slack": {
                    "Type": "Task",
                    "Resource": sendFindingArn,
                    "Parameters": {
                        "comment": "Others fields from the GuardDuty / Security Hub finding",
                        "severity.$": "$.detail.findings[0].Severity.Label",
                        "Account_ID.$": "$.account",
                        "Finding_ID.$": "$.id",
                        "Finding_Type.$": "$.detail.findings[0].Types",
                        "Region.$": "$.region",
                        "Finding_description.$": "$.detail.findings[0].Description"
                    },
                    "End": true
                },
            },
            "TimeoutSeconds": 300
        })
    })
});
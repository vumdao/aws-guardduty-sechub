import * as aws from '@pulumi/aws';
import { region } from './config';
import * as sfn from './sfn';


const event_role = new aws.iam.Role('GDEventBridgeRole', {
    description: 'Role to trigger statemachine',
    name: `${region}-gd-eventbridge`,
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Sid: "",
            Principal: {
                Service: "events.amazonaws.com",
            },
        }]
    }),
    tags: {
        'Name': `${region}-gd-eventbridge`,
        'stack': 'pulumi-iam-role'
    }
});

const event_policy = new aws.iam.RolePolicy("allow-start-sfn", {
    role: event_role,
    policy: {
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "AllowSfnStatement",
                Effect: "Allow",
                Resource: sfn.high_severity_finding_sfn.arn,
                Action: "states:StartExecution"
            }
        ]
    },
}, {parent: event_role});

const event_gd = new aws.cloudwatch.EventRule('GuardDutyFindingsEvent', {
    description: 'Start step function for incoming GuardDuty event',
    eventPattern: `{
        "detail-type": ["Security Hub Findings - Imported"],
        "source": ["aws.securityhub"],
        "region": ["us-west-2"],
        "detail": {
           "findings": {
                "Severity": {
                    "Label": ["HIGH", "CRITICAL"]
                }
            }
        }
    }`,
    name: `${region}-gd-findings`,
    roleArn: event_role.arn,
    tags: {
        'Name': `${region}-gd-findings`,
        'stack': 'pulumi-eventbridge'
    }
});
;
let event_target = new aws.cloudwatch.EventTarget('GuardDutyFindingsEventTarget', {
    rule: event_gd.name,
    arn: sfn.high_severity_finding_sfn.arn,
    roleArn: event_role.arn
});

const event_catch_ip = new aws.cloudwatch.EventRule('guardduty-catch-ipv4', {
    description: 'Security Hub - GuardDuty findings with remote IP',
    eventPattern: `{
        "source": ["aws.securityhub"],
        "region": ["us-west-2"],
        "detail-type": ["Security Hub Findings - Imported"],
        "detail": {
           "findings": {
                "ProductFields": {
                    "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4": [{
                        "exists": true
                    }]
                }
            }
        }
    }`,
    name: `${region}-gd-catch-ipv4`,
    roleArn: event_role.arn,
    tags: {
        'Name': `${region}-gd-catch-ipv4`,
        'stack': 'pulumi-eventbridge'
    }
});

let event_catch_ip_target = new aws.cloudwatch.EventTarget('guardduty-catch-ipv4-target', {
    rule: event_catch_ip.name,
    arn: sfn.record_ip_sfn.arn,
    roleArn: event_role.arn
});

const event_sch_pruning = new aws.cloudwatch.EventRule('ScheduledPruningRule', {
    description: 'Schedule pruning expired IPs',
    scheduleExpression: 'rate(10080 minutes)',
    name: `${region}-gd-sch-pruning`,
    roleArn: event_role.arn,
    tags: {
        'Name': `${region}-gd-sch-pruning`,
        'stack': 'pulumi-eventbridge'
    }
});

let event_sch_pruning_target = new aws.cloudwatch.EventTarget('ScheduledPruningTarget', {
    rule: event_sch_pruning.name,
    arn: sfn.pruning_ip_sfn.arn,
    roleArn: event_role.arn
});
import * as aws from '@pulumi/aws';
import { region } from './config';


export const nf_rg = new aws.networkfirewall.RuleGroup('NetWorkFireWallRuleGroup', {
    description: 'GuardDuty network firewall rule group',
    name: `${region}-guardduty-nf-rg`,
    capacity: 100,
    type: 'STATELESS',
    ruleGroup: {
        rulesSource: {
            statelessRulesAndCustomActions: {
                statelessRules: [
                    {
                        priority: 10,
                        ruleDefinition: {
                            actions: ['aws:drop'],
                            matchAttributes: {
                                destinations: [
                                    { addressDefinition: '127.0.0.1/32'}
                                ]
                            }
                        }
                    }
                ]
            }
        }
    },
    tags: {
        'Name': `${region}-guardduty-nf-rg`,
        'stack': 'pulumi-network-firewall'
    }
});

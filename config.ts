import * as pulumi from '@pulumi/pulumi';

let config = new pulumi.Config();
export const webhook_url: string = config.require('webhook_url');
export const region: string = 'us-west-2';
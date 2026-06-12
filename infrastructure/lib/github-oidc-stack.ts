import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface GitHubOidcStackProps extends cdk.StackProps {
  repositoryOwner: string;
  repositoryName: string;
}

export class GitHubOidcStack extends cdk.Stack {
  public readonly deploymentRole: iam.Role;

  constructor(scope: Construct, id: string, props: GitHubOidcStackProps) {
    super(scope, id, props);

    // Apply standard tags
    cdk.Tags.of(this).add('Application', 'cassiecayphotography');
    cdk.Tags.of(this).add('Environment', 'production');
    cdk.Tags.of(this).add('ManagedBy', 'cdk');
    cdk.Tags.of(this).add('Repository', `${props.repositoryOwner}/${props.repositoryName}`);

    // Reference existing GitHub OIDC provider (shared across all repos in this account)
    // The provider was created previously - we only need one per AWS account
    const githubOidcProvider = iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(
      this,
      'GitHubOidcProvider',
      `arn:aws:iam::${cdk.Aws.ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com`
    );

    // Create IAM role for GitHub Actions
    this.deploymentRole = new iam.Role(this, 'GitHubActionsDeploymentRole', {
      roleName: 'CassiePhotoGitHubActionsDeploymentRole',
      assumedBy: new iam.FederatedPrincipal(
        githubOidcProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
            // Scope the trust to exactly the two subjects that legitimately deploy,
            // instead of `repo:OWNER/REPO:*` (any workflow/branch/PR in the repo).
            //   - the deploy job runs under `environment: production`, so GitHub mints
            //     its OIDC token with sub `...:environment:production` (verified via
            //     CloudTrail AssumeRoleWithWebIdentity on this role).
            //   - the notify-failure job has no environment, so on a main-branch run
            //     its sub is `...:ref:refs/heads/main`.
            // StringEquals (not StringLike) since these are exact, wildcard-free values.
            'token.actions.githubusercontent.com:sub': [
              `repo:${props.repositoryOwner}/${props.repositoryName}:environment:production`,
              `repo:${props.repositoryOwner}/${props.repositoryName}:ref:refs/heads/main`,
            ],
          },
        },
        'sts:AssumeRoleWithWebIdentity'
      ),
      description: 'Role for GitHub Actions to deploy Cassie Cay Photography static site',
      maxSessionDuration: cdk.Duration.hours(1),
    });

    // S3 permissions for deployment (both new CDK bucket and existing bucket for migration)
    this.deploymentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'S3DeploymentPermissions',
        effect: iam.Effect.ALLOW,
        actions: [
          's3:PutObject',
          's3:GetObject',
          's3:DeleteObject',
          's3:ListBucket',
          's3:GetBucketLocation',
        ],
        resources: [
          // Site content bucket
          `arn:aws:s3:::cassiecayphotography.com-site-content`,
          `arn:aws:s3:::cassiecayphotography.com-site-content/*`,
        ],
      })
    );

    // CloudFormation permissions to read stack outputs
    this.deploymentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'CloudFormationReadPermissions',
        effect: iam.Effect.ALLOW,
        actions: [
          'cloudformation:DescribeStacks',
        ],
        resources: [
          `arn:aws:cloudformation:us-east-1:${cdk.Aws.ACCOUNT_ID}:stack/CassiePhoto*/*`,
        ],
      })
    );

    // CloudFront permissions for cache invalidation
    this.deploymentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'CloudFrontInvalidation',
        effect: iam.Effect.ALLOW,
        actions: [
          'cloudfront:CreateInvalidation',
          'cloudfront:GetInvalidation',
          'cloudfront:ListInvalidations',
        ],
        resources: ['*'], // CloudFront doesn't support resource-level permissions for invalidations
      })
    );

    // SES permissions for deploy notifications
    this.deploymentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'SESNotificationPermissions',
        effect: iam.Effect.ALLOW,
        actions: ['ses:SendEmail'],
        resources: ['*'],
        conditions: {
          StringEquals: {
            'ses:FromAddress': 'no-reply@cassiecayphotography.com',
          },
        },
      })
    );

    // Outputs
    new cdk.CfnOutput(this, 'DeploymentRoleArn', {
      value: this.deploymentRole.roleArn,
      description: 'ARN of the GitHub Actions deployment role',
      exportName: 'CassiePhotoGitHubActionsRoleArn',
    });

    new cdk.CfnOutput(this, 'OidcProviderArn', {
      value: `arn:aws:iam::${cdk.Aws.ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com`,
      description: 'ARN of the GitHub OIDC provider (shared)',
    });
  }
}

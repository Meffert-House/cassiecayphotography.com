import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import { Construct } from 'constructs';

export interface StaticSiteStackProps extends cdk.StackProps {
  domainName: string;
  hostedZoneId?: string;
  /**
   * Skip domain setup (certificate, aliases, DNS records).
   * Use this for initial deployment when migrating from existing infrastructure.
   * After migration, set to false and redeploy to attach the domain.
   */
  skipDomainSetup?: boolean;
}

export class StaticSiteStack extends cdk.Stack {
  public readonly bucket: s3.Bucket;
  public readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props: StaticSiteStackProps) {
    super(scope, id, props);

    // Apply standard tags
    cdk.Tags.of(this).add('Application', 'cassiecayphotography');
    cdk.Tags.of(this).add('Environment', 'production');
    cdk.Tags.of(this).add('ManagedBy', 'cdk');
    cdk.Tags.of(this).add('Repository', 'Meffert-House/cassiecayphotography.com');

    const skipDomain = props.skipDomainSetup ?? false;

    // Look up the hosted zone (only if setting up domain)
    const hostedZone = skipDomain ? undefined : route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.domainName,
    });

    // Create S3 bucket for static site content
    this.bucket = new s3.Bucket(this, 'SiteBucket', {
      bucketName: `${props.domainName}-site-content`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
    });

    // Create ACM certificate for HTTPS (only if setting up domain)
    const certificate = skipDomain ? undefined : new acm.Certificate(this, 'SiteCertificate', {
      domainName: props.domainName,
      subjectAlternativeNames: [`www.${props.domainName}`],
      validation: acm.CertificateValidation.fromDns(hostedZone!),
    });

    // Create Origin Access Control for CloudFront -> S3
    const oac = new cloudfront.S3OriginAccessControl(this, 'OAC', {
      signing: cloudfront.Signing.SIGV4_ALWAYS,
    });

    // Security headers policy for all responses
    const securityHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'SecurityHeadersPolicy', {
      responseHeadersPolicyName: 'cassiecayphoto-security-headers',
      comment: 'Security headers for cassiecayphotography.com',
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          contentSecurityPolicy: [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' blob: https://www.google.com https://www.gstatic.com https://www.recaptcha.net https://www.googletagmanager.com",
            "style-src 'self' 'unsafe-inline' https://use.typekit.net https://p.typekit.net",
            "font-src 'self' data: https://use.typekit.net",
            "img-src 'self' data: https:",
            "connect-src 'self' https://*.lambda-url.us-east-1.on.aws https://www.google.com https://www.google-analytics.com",
            "frame-src https://www.google.com https://www.recaptcha.net",
            "worker-src 'self' blob:",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
          ].join('; '),
          override: true,
        },
        frameOptions: {
          frameOption: cloudfront.HeadersFrameOption.DENY,
          override: true,
        },
        contentTypeOptions: {
          override: true,
        },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.days(365),
          includeSubdomains: true,
          preload: true,
          override: true,
        },
        xssProtection: {
          protection: true,
          modeBlock: true,
          override: true,
        },
      },
      customHeadersBehavior: {
        customHeaders: [
          {
            header: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
            override: true,
          },
        ],
      },
    });

    // CloudFront Function to handle URL redirects for SEO canonical consistency
    const urlRedirectFunction = skipDomain ? undefined : new cloudfront.Function(this, 'UrlRedirectFunction', {
      code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var request = event.request;
  var host = request.headers.host.value;

  // Redirect www to non-www
  if (host.startsWith('www.')) {
    var newHost = host.substring(4);
    return {
      statusCode: 301,
      statusDescription: 'Moved Permanently',
      headers: {
        'location': { value: 'https://' + newHost + request.uri }
      }
    };
  }

  // Redirect /index.html to / for canonical URL consistency
  if (request.uri === '/index.html') {
    return {
      statusCode: 301,
      statusDescription: 'Moved Permanently',
      headers: {
        'location': { value: 'https://' + host + '/' }
      }
    };
  }

  return request;
}
      `),
      functionName: 'cassiecayphoto-url-redirect',
      comment: 'Redirects www to non-www and /index.html to / for canonical consistency',
    });

    // Create CloudFront distribution
    this.distribution = new cloudfront.Distribution(this, 'SiteDistribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket, {
          originAccessControl: oac,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
        compress: true,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: securityHeadersPolicy,
        // Attach URL redirect function only when domain is configured
        ...(urlRedirectFunction ? {
          functionAssociations: [{
            function: urlRedirectFunction,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          }],
        } : {}),
      },
      // Only set domain names and certificate when not skipping domain setup
      ...(skipDomain ? {} : {
        domainNames: [props.domainName, `www.${props.domainName}`],
        certificate,
      }),
      defaultRootObject: 'index.html',
      errorResponses: [
        {
          httpStatus: 404,
          responseHttpStatus: 404,
          responsePagePath: '/404.html',
          ttl: cdk.Duration.hours(1),
        },
        {
          httpStatus: 403,
          responseHttpStatus: 404,
          responsePagePath: '/404.html',
          ttl: cdk.Duration.hours(1),
        },
      ],
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100, // US, Canada, Europe
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
    });

    // Create DNS records only when not skipping domain setup
    if (!skipDomain && hostedZone) {
      // Create Route 53 A record for apex domain
      new route53.ARecord(this, 'SiteARecord', {
        zone: hostedZone,
        target: route53.RecordTarget.fromAlias(
          new targets.CloudFrontTarget(this.distribution)
        ),
      });

      // Create Route 53 A record for www subdomain
      new route53.ARecord(this, 'SiteWwwARecord', {
        zone: hostedZone,
        recordName: 'www',
        target: route53.RecordTarget.fromAlias(
          new targets.CloudFrontTarget(this.distribution)
        ),
      });

      // Create Route 53 AAAA records for IPv6
      new route53.AaaaRecord(this, 'SiteAaaaRecord', {
        zone: hostedZone,
        target: route53.RecordTarget.fromAlias(
          new targets.CloudFrontTarget(this.distribution)
        ),
      });

      new route53.AaaaRecord(this, 'SiteWwwAaaaRecord', {
        zone: hostedZone,
        recordName: 'www',
        target: route53.RecordTarget.fromAlias(
          new targets.CloudFrontTarget(this.distribution)
        ),
      });
    }

    // CloudWatch error alarms (4xx + 5xx) and their SNS email topic were removed.
    // The 4xx alarm was too noisy on a static site (bot/crawler 404s) and was deleted
    // out-of-band; deleting its SNS topic alongside it also orphaned the 5xx alarm's
    // notification. Per the owner's decision, error alerting is retired here entirely
    // (monitored elsewhere). This makes the source match production and clears the
    // related stack drift.

    // Outputs
    new cdk.CfnOutput(this, 'BucketName', {
      value: this.bucket.bucketName,
      description: 'S3 bucket name for site content',
      exportName: 'CassiePhotoSiteBucketName',
    });

    new cdk.CfnOutput(this, 'DistributionId', {
      value: this.distribution.distributionId,
      description: 'CloudFront distribution ID',
      exportName: 'CassiePhotoDistributionId',
    });

    new cdk.CfnOutput(this, 'DistributionDomainName', {
      value: this.distribution.distributionDomainName,
      description: 'CloudFront distribution domain name',
    });

    new cdk.CfnOutput(this, 'SiteUrl', {
      value: `https://${props.domainName}`,
      description: 'Website URL',
    });
  }
}

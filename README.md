# AWS MSK IAM SASL Signer for .NET
 
[![Build status](https://github.com/aws/aws-msk-iam-sasl-signer-net/actions/workflows/build.yml/badge.svg)](https://github.com/aws/aws-msk-iam-sasl-signer-net/actions/workflows/build.yml) 
[![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/aws/aws-msk-iam-sasl-signer-net/blob/main/LICENSE.txt)
[![Security Scan](https://github.com/aws/aws-msk-iam-sasl-signer-net/actions/workflows/securityscan.yml/badge.svg?branch=main)](https://github.com/aws/aws-msk-iam-sasl-signer-net/actions/workflows/securityscan.yml)

`aws-msk-iam-sasl-signer-net` is the AWS MSK IAM SASL Signer for .NET. 

This libary vends encoded IAM v4 signatures which can be used as IAM Auth tokens to authenticate against an MSK cluster. 
 
The AWS MSK IAM SASL Signer for .NET has a target framework of [netstandard2.0](https://learn.microsoft.com/en-us/dotnet/standard/net-standard?tabs=net-standard-2-0)
 
Check out the [release notes](https://github.com/aws/aws-msk-iam-sasl-signer-net/blob/main/CHANGELOG.md) for information about the latest bug
fixes, updates, and features added to the library.
 
Jump To:
* [Getting Started](#getting-started)
* [Getting Help](#getting-help)
* [Feedback and Contributing](#contributing)
* [More Resources](#resources)
 
 
## <a name="getting-started"></a> Getting started
To get started working with the AWS MSK IAM SASL Signer for .NET with your Kafka client library please follow below code sample -
 
###### Add Dependencies
 
 AWS MSK IAM SASL SIGNER is distribured via NuGet. We provide the package [AWS.MSK.Auth](https://www.nuget.org/packages/AWS.MSK.Auth/) which can be imported via NuGet in your development environment. 
 
###### Write Code
 
For example, you can use the signer library to generate IAM based OAUTH token with [confluent-kafka-dotnet](https://github.com/confluentinc/confluent-kafka-dotnet) library as below -
 
 ```cs
    var producerConfig = new ProducerConfig
    {
        BootstrapServers = < BOOTSTRAP - SERVER - HERE >,
        SecurityProtocol = SecurityProtocol.SaslSsl,
        SaslMechanism = SaslMechanism.OAuthBearer
    };

    AWSMSKAuthTokenGenerator mskAuthTokenGenerator = new AWSMSKAuthTokenGenerator();

    //Callback to handle OAuth bearer token refresh. It fetches the OAUTH Token from the AWSMSKAuthTokenGenerator class. 
    void OauthCallback(IClient client, string cfg)
    {
        try
        {
            var (token, expiryMs) = mskAuthTokenGenerator.GenerateAuthToken(Amazon.RegionEndpoint.USEast1);
            client.OAuthBearerSetToken(token, expiryMs, "DummyPrincipal");
        }
        catch (Exception e)
        {
            client.OAuthBearerSetTokenFailure(e.ToString());
        }
    }

    var producer = new ProducerBuilder<string, string>(producerConfig)
                        .SetOAuthBearerTokenRefreshHandler(OauthCallback).Build();
            try
            {
                var deliveryReport = await producer.ProduceAsync("test-topic", new Message<string, string> { Value = "Hello from .NET" });

                Console.WriteLine($"Produced message to {deliveryReport.TopicPartitionOffset}");
            }
            catch (ProduceException<string, string> e)
            {
                Console.WriteLine($"failed to deliver message: {e.Message} [{e.Error.Code}]");
            }
 ```
 
## More examples of generating auth token
 
### Specifying an alternate credential profile for a client
 
```cs
AWSMSKAuthTokenGenerator mskAuthTokenGenerator = new AWSMSKAuthTokenGenerator();
var (token, expiryMs) = mskAuthTokenGenerator.GenerateAuthTokenFromProfile("profileName", Amazon.RegionEndpoint.USEast1);
```
 
### Specifying a role based credential for a client
 
```cs
AWSMSKAuthTokenGenerator mskAuthTokenGenerator = new AWSMSKAuthTokenGenerator();
var (token, expiryMs) = mskAuthTokenGenerator.GenerateAuthTokenFromRole(Amazon.RegionEndpoint.USEast1, "roleName", "roleSessioName");
```

Note that roleSessionName is optional here. A default name is used if not specified. This uses the default token expiry, and creates a new STS client for every invocation. 
For higher configurability, use the method mentioned below which takes a credentials provider as an input. This allows you to bring your own credentials for signing the request. 
 
### <a name="credential-provider-method"></a> Specifying AWS Credential Provider for a client
 
```cs
AWSMSKAuthTokenGenerator mskAuthTokenGenerator = new AWSMSKAuthTokenGenerator();
var (token, expiryMs) = mskAuthTokenGenerator.GenerateAuthTokenFromCredentialsProvider(() => new BasicAWSCredentials("secretKey", "accessKey"), Amazon.RegionEndpoint.USEast1);
```
 
## <a name="troubleshooting"></a> Troubleshooting

### <a name="debug-creds"></a> Finding out which identity is being used

When using default credentials, You may receive an Access denied error and there may be some doubt as to which credential is being exactly used. The credential may be sourced from a role ARN, EC2 instance profile, credential profile etc.

You can set the optional parameter awsDebugCreds set to true before getting the token in such cases. 

```cs
var (token, expiryMs) = mskAuthTokenGenerator.GenerateAuthToken(Amazon.RegionEndpoint.USEast1, awsDebugCreds:true);

```

The client library will print a debug log of the form:

```
"Credentials Identity: UserId: ABCD:test124, Account: 1234567890, Arn: arn:aws:sts::1234567890:assumed-role/abc/test124"
```
 
## <a name="getting-help"></a> Getting Help
 
Please use these community resources for getting help. We use the GitHub issues
for tracking bugs and feature requests.
 
* Ask us a [question](https://github.com/aws/aws-msk-iam-sasl-signer-net/discussions/new?category=q-a) or open a [discussion](https://github.com/aws/aws-msk-iam-sasl-signer-net/discussions/new?category=general).
* If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-msk-iam-sasl-signer-net/issues/new/choose).
* Open a support ticket with [AWS Support](http://docs.aws.amazon.com/awssupport/latest/user/getting-started.html).
 
This repository provides a pluggable library with any .NET Kafka client for SASL/OAUTHBEARER mechanism. For more information about SASL/OAUTHBEARER mechanism please go to [KIP 255](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=75968876).
 
### Opening Issues
 
If you encounter a bug with the AWS MSK IAM SASL Signer for .NET we would like to hear about it.
Search the [existing issues][Issues] and see
if others are also experiencing the same issue before opening a new issue. Please
include the version of AWS MSK IAM SASL Signer for .NET, and OS you’re using. Please
also include reproduction case when appropriate.
 
The GitHub issues are intended for bug reports and feature requests. For help
and questions with using AWS MSK IAM SASL Signer for .NET, please make use of the resources listed
in the [Getting Help](#getting-help) section.
Keeping the list of open issues lean will help us respond in a timely manner.
 
## <a name="contributing"></a> Feedback and contributing
 
The AWS MSK IAM SASL Signer for .NET will use GitHub [Issues] to track feature requests and issues with the library. In addition, we'll use GitHub [Projects] to track large tasks spanning multiple pull requests, such as refactoring the library's internal request lifecycle. You can provide feedback to us in several ways.
 
**GitHub issues**. To provide feedback or report bugs, file GitHub [Issues] on the library. This is the preferred mechanism to give feedback so that other users can engage in the conversation, +1 issues, etc. Issues you open will be evaluated, and included in our roadmap for the GA launch.
 
**Contributing**. You can open pull requests for fixes or additions to the AWS MSK IAM SASL Signer for .NET. All pull requests must be submitted under the Apache 2.0 license and will be reviewed by a team member before being merged in. Accompanying unit tests, where possible, are appreciated.
 
## <a name="resources"></a> Resources
 
[Developer Guide](https://aws.github.io/aws-msk-iam-sasl-signer-net/docs/) - Use this document to learn how to get started and
use the AWS MSK IAM SASL Signer for .NET.
 
[Service Documentation](https://docs.aws.amazon.com/msk/latest/developerguide/getting-started.html) - Use this
documentation to learn how to interface with AWS MSK.
 
[Issues] - Report issues, submit pull requests, and get involved
(see [Apache 2.0 License][license])
 
[Issues]: https://github.com/aws/aws-msk-iam-sasl-signer-net/issues
[Projects]: https://github.com/aws/aws-msk-iam-sasl-signer-net/projects
[CHANGELOG]: https://github.com/aws/aws-msk-iam-sasl-signer-net/blob/main/CHANGELOG.md
[license]: http://aws.amazon.com/apache2.0/
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.Runtime.Endpoints;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Auth;
using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using System.Globalization;

namespace AWS.MSK.Auth
{
    /// <summary>
    /// Provides Auth tokens for IAM authentication against an MSK cluster.
    /// </summary>
    public class AWSMSKAuthTokenGenerator
    {
        private const string ServiceName = "kafka-cluster";
        private const string HTTPMethod = "GET";
        private const string Scheme = "https";
        private const string ActionKey = "Action";
        private const string ActionValue = "kafka-cluster:Connect";
        private const string XAmzExpires = "X-Amz-Expires";
        private const string XAmzSecurityToken = "X-Amz-Security-Token";
        private const string HostnameStringFormat = "kafka.{0}.amazonaws.com";

        private static readonly TimeSpan ExpiryDuration = TimeSpan.FromSeconds(900);

        private AmazonSecurityTokenServiceClient _stsClient;
        private readonly ILogger<AWSMSKAuthTokenGenerator> _logger;

        /// <summary>
        /// Constructor for AWSMSKAuthTokenGenerator.
        /// </summary>
        /// <param name="stsClient">Amazon STS Client</param>
        /// <param name="loggerFactory">Injectable logger factory</param>
        public AWSMSKAuthTokenGenerator(AmazonSecurityTokenServiceClient? stsClient = null, ILoggerFactory? loggerFactory = null)
        {

            if (stsClient != null)
            {
                _stsClient = stsClient;
            }
            else
            {
                _stsClient = new Amazon.SecurityToken.AmazonSecurityTokenServiceClient();
            }

            if (loggerFactory != null)
            {
                _logger = loggerFactory.CreateLogger<AWSMSKAuthTokenGenerator>();
            }
            else
            {
                _logger = NullLoggerFactory.Instance.CreateLogger<AWSMSKAuthTokenGenerator>();
            }
        }

        /// <summary>
        /// AWS4PreSignedUrlSigner is built around operation request objects.
        /// This request type will only be used to generate the signed token.
        /// It will never be used to make an actual request to cluster
        /// </summary>
        private class GenerateMSKAuthTokenRequest : AmazonWebServiceRequest
        {
            public GenerateMSKAuthTokenRequest()
            {
                ((IAmazonWebServiceRequest)this).SignatureVersion = SignatureVersion.SigV4;
            }
        }

        /// <summary>
        /// Generate a token for IAM authentication to an MSK cluster.
        /// <remarks>
        /// Token generation requires AWSCredentials and an AWS RegionEndpoint.
        /// AWSCredentials will be loaded from the application's default configuration,
        /// and if unsuccessful from the Instance Profile service on an EC2 instance.
        /// </remarks>
        /// </summary>
        /// <param name="region">Region of the MSK cluster</param>
        /// <returns> An Auth token in string format </returns>
        public (string, long) GenerateAuthToken(RegionEndpoint region)
        {
            AWSCredentials credentials = FallbackCredentialsFactory.GetCredentials();

            return GenerateAuthTokenFromCredentialsProvider(() => credentials, region);
        }

        /// <summary>
        /// Generate a token for IAM authentication to an MSK cluster using an IAM Role
        /// <remarks>
        /// This method generates an Auth token using the roleArn provided with the provided SessionName (optional). If SessionName is not provided,
        /// a default session name of "MSKSASLDefaultSession" is used. Note that this method uses the STS global endpoint to assume role to sign the credentials.
        /// For more involved use cases like using regional endpoints, consider using the GenerateAuthTokenFromCredentialsProvider method directly. 
        /// </remarks>
        /// </summary>
        /// <param name="region">Region of the MSK cluster</param>
        /// <param name="roleArn">ARN of the role which needs to be assumed for signing the request</param>
        /// <param name="sessionName">An optional session name</param>
        /// 
        /// <returns> An Auth token in string format </returns>
        public async Task<(string, long)> GenerateAuthTokenFromRoleAsync(RegionEndpoint region, String roleArn, String sessionName = "MSKSASLDefaultSession")
        {
            var assumeRoleReq = new AssumeRoleRequest()
            {
                RoleSessionName = sessionName,
                RoleArn = roleArn
            };

            AssumeRoleResponse assumeRoleResponse = await _stsClient.AssumeRoleAsync(assumeRoleReq, default);

            var stsCredentials = assumeRoleResponse.Credentials;

            return GenerateAuthTokenFromCredentialsProvider(() => new SessionAWSCredentials(stsCredentials.AccessKeyId, stsCredentials.SecretAccessKey, stsCredentials.SessionToken), region);
        }

        /// <summary>
        /// Generate a token for IAM authentication to an MSK cluster using an IAM Profile
        /// <remarks>
        /// This method generates an Auth token using and IAM Profile 
        /// </remarks>
        /// </summary>
        /// <param name="profileName">AWS Credentials to sign the request will be fetched from this profile</param>
        /// <param name="region">Region of the MSK cluster</param>
        /// <returns> An Auth token in string format </returns>

        public (string, long) GenerateAuthTokenFromProfile(String profileName, RegionEndpoint region)
        {
            var chain = new CredentialProfileStoreChain();
            AWSCredentials awsCredentials;
            
            if (chain.TryGetAWSCredentials(profileName, out awsCredentials))
            {
                return GenerateAuthTokenFromCredentialsProvider(() => awsCredentials, region);
            }
            else
            {
                throw new ArgumentException("Could not find credentials using profile " + profileName);
            }
        }

        /// <summary>
        /// Generate a token for IAM authentication to an MSK cluster using client provided AWS credentials. 
        /// <remarks>
        /// </summary>
        /// <param name="credentialsProvider">A Function which returns AWSCredentials to be used for signing the request</param>
        /// <param name="region">Region of the MSK cluster</param>
        /// <returns> An Auth token in String format </returns>
        public (string, long) GenerateAuthTokenFromCredentialsProvider(Func<AWSCredentials> credentialsProvider, RegionEndpoint region)
        {
            if (credentialsProvider == null)
            {
                throw new ArgumentNullException(nameof(credentialsProvider));
            }
                
            if (region == null)
            {
                throw new ArgumentNullException(nameof(region));
            }
               
            AWSCredentials credentials = credentialsProvider.Invoke();

            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            _logger.LogDebug("Generating auth token using credentials with access key id" + credentials.GetCredentials().AccessKey);

            GenerateMSKAuthTokenRequest authTokenRequest = new GenerateMSKAuthTokenRequest();
            IRequest request = new DefaultRequest(authTokenRequest, ServiceName);

            request.UseQueryString = true;
            request.HttpMethod = HTTPMethod;
            request.Parameters.Add(XAmzExpires, ExpiryDuration.TotalSeconds.ToString(CultureInfo.InvariantCulture));
            request.Parameters.Add(ActionKey, ActionValue);
            string hostName = String.Format(HostnameStringFormat, region.SystemName);
            request.Endpoint = new UriBuilder(Scheme, hostName).Uri;

            var immutableCredentials = credentials.GetCredentials();
            if (immutableCredentials.UseToken)
            {
                request.Parameters[XAmzSecurityToken] = immutableCredentials.Token;
            }

            var signingResult = AWS4PreSignedUrlSigner.SignRequest(request, null, new RequestMetrics(), immutableCredentials.AccessKey,
                immutableCredentials.SecretKey, ServiceName, region.SystemName);

            var authorization = "&" + signingResult.ForQueryParameters;
            var url = AmazonServiceClient.ComposeUrl(request);

            String userAgent = "&User-Agent=" + getUserAgent();
            String authTokenString = url.AbsoluteUri + userAgent + authorization;

            _logger.LogDebug("Signed url for MSK cluster: " + authTokenString);

            byte[] byteArray = System.Text.UTF8Encoding.UTF8.GetBytes(authTokenString);

            long expiryMs = new DateTimeOffset(signingResult.DateTime.Add(ExpiryDuration)).ToUnixTimeSeconds() * 1000;
            return (Convert.ToBase64String(byteArray).Replace('+', '-').Replace('/', '_').TrimEnd('='),  expiryMs);
        }

        private static String getUserAgent()
        {
            return "aws-msk-iam-sasl-signer-net-" + SignerVersion.CurrentVersion;
        }

    }
}
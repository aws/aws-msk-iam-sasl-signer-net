﻿// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Text;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.Runtime.Credentials;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Auth;
using Amazon.Runtime.Internal.Util;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using AWS.MSK.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

public class AWSMSKAuthTokenGenerator
{
    private const string ServiceName = "kafka-cluster";
    private const string HttpMethod = "GET";
    private const string Scheme = "https";
    private const string ActionKey = "Action";
    private const string ActionValue = "kafka-cluster:Connect";
    private const string XAmzExpires = "X-Amz-Expires";
    private const string XAmzSecurityToken = "X-Amz-Security-Token";
    private const string HostnameStringFormat = "kafka.{0}.amazonaws.com";

    private static readonly TimeSpan ExpiryDuration = TimeSpan.FromSeconds(900);

    private AmazonSecurityTokenServiceClient? _stsClient;
    private RegionEndpoint? _stsClientRegion;
    private readonly ILogger<AWSMSKAuthTokenGenerator> _logger;
    private readonly Func<DateTime> _timeProvider;

    /// <summary>
    /// Constructor for AWSMSKAuthTokenGenerator.
    /// </summary>
    /// <param name="stsClient">Amazon STS Client</param>
    /// <param name="loggerFactory">Injectable logger factory</param>
    /// <param name="timeProvider">Injectable time provider</param>
    public AWSMSKAuthTokenGenerator(
        AmazonSecurityTokenServiceClient? stsClient = null,
        ILoggerFactory? loggerFactory = null,
        Func<DateTime>? timeProvider = null)
    {
        _stsClient = stsClient;
        _stsClientRegion = stsClient?.Config?.RegionEndpoint;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<AWSMSKAuthTokenGenerator>();
        _timeProvider = timeProvider ?? (static () => DateTime.UtcNow);
    }

    /// <summary>
    /// AWS4PreSignedUrlSigner is built around operation request objects.
    /// This request type will only be used to generate the signed token.
    /// It will never be used to make an actual request to cluster
    /// </summary>
    private class GenerateMskAuthTokenRequest : AmazonWebServiceRequest
    {
        public GenerateMskAuthTokenRequest() =>
            ((IAmazonWebServiceRequest)this).SignatureVersion = SignatureVersion.SigV4;
    }

#region GenerateAuthToken

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster.
    /// <remarks>
    /// Token generation requires AWSCredentials and an AWS RegionEndpoint.
    /// AWSCredentials will be loaded from the application's default configuration,
    /// and if unsuccessful from the Instance Profile service on an EC2 instance.
    /// </remarks>
    /// </summary>
    /// <param name="region">Region of the MSK cluster</param>
    /// <param name="awsDebugCreds">Whether to log caller identity used for generating auth token. Default value is false.
    ///                             Note that this only works when LogLevel for logger is configured as Debug.
    ///                             Using this in Production is discouraged as it creates a new STS client on every invocation</param>
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public (string, long) GenerateAuthToken(RegionEndpoint region, bool awsDebugCreds = false)
    {
        AWSCredentials credentials = DefaultAWSCredentialsIdentityResolver.GetCredentials();

        LogCredentialsIdentity(credentials, region, awsDebugCreds).GetAwaiter().GetResult();

        return GenerateAuthTokenFromCredentialsProvider(() => credentials, region, false).GetAwaiter().GetResult();
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
    /// <param name="awsDebugCreds">Whether to log caller identity used for generating auth token. Default value is false.
    ///                             Note that this only works when LogLevel for logger is configured as Debug.
    ///                             Using this in Production is discouraged as it creates a new STS client on every invocation</param>
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public async Task<(string, long)> GenerateAuthTokenAsync(RegionEndpoint region, bool awsDebugCreds = false)
    {
        AWSCredentials credentials = await DefaultAWSCredentialsIdentityResolver.GetCredentialsAsync();

        await LogCredentialsIdentity(credentials, region, awsDebugCreds);

        return await GenerateAuthTokenFromCredentialsProvider(() => credentials, region);
    }

#endregion GenerateAuthToken

#region GenerateAuthTokenFromRole

    private AmazonSecurityTokenServiceClient GetStsClient(RegionEndpoint region)
    {
        if (_stsClient is null || _stsClientRegion != region)
        {
            _stsClient = new AmazonSecurityTokenServiceClient(region);
            _stsClientRegion = region;
        }

        return _stsClient;
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
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public (string, long) GenerateAuthTokenFromRole(RegionEndpoint region, string roleArn, string sessionName = "MSKSASLDefaultSession")
    {
        var assumeRoleReq = new AssumeRoleRequest
        {
            RoleSessionName = sessionName,
            RoleArn = roleArn
        };

        var assumeRoleResponse = GetStsClient(region).AssumeRoleAsync(assumeRoleReq).GetAwaiter().GetResult();

        var stsCredentials = assumeRoleResponse.Credentials;

        return GenerateAuthTokenFromCredentialsProvider(
            () => new SessionAWSCredentials(stsCredentials.AccessKeyId, stsCredentials.SecretAccessKey, stsCredentials.SessionToken), region, false)
            .GetAwaiter().GetResult();
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
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public async Task<(string, long)> GenerateAuthTokenFromRoleAsync(RegionEndpoint region, string roleArn, string sessionName = "MSKSASLDefaultSession")
    {
        var assumeRoleReq = new AssumeRoleRequest
        {
            RoleSessionName = sessionName,
            RoleArn = roleArn
        };

        var assumeRoleResponse = await GetStsClient(region).AssumeRoleAsync(assumeRoleReq);

        var stsCredentials = assumeRoleResponse.Credentials;

        return await GenerateAuthTokenFromCredentialsProvider(
            () => new SessionAWSCredentials(stsCredentials.AccessKeyId, stsCredentials.SecretAccessKey,
                stsCredentials.SessionToken), region);
    }

#endregion GenerateAuthTokenFromRole

#region GenerateAuthTokenFromProfile

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using an IAM Profile
    /// <remarks>
    /// This method generates an Auth token using and IAM Profile
    /// </remarks>
    /// </summary>
    /// <param name="profileName">AWS Credentials to sign the request will be fetched from this profile</param>
    /// <param name="region">Region of the MSK cluster</param>
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public (string, long) GenerateAuthTokenFromProfile(string profileName, RegionEndpoint region)
    {
        var chain = new CredentialProfileStoreChain();

        if (chain.TryGetAWSCredentials(profileName, out var awsCredentials))
        {
            return GenerateAuthTokenFromCredentialsProvider(() => awsCredentials, region, false).GetAwaiter().GetResult();
        }

        throw new ArgumentException($"Could not find credentials using profile {profileName}");
    }

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using an IAM Profile
    /// <remarks>
    /// This method generates an Auth token using and IAM Profile
    /// </remarks>
    /// </summary>
    /// <param name="profileName">AWS Credentials to sign the request will be fetched from this profile</param>
    /// <param name="region">Region of the MSK cluster</param>
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public Task<(string, long)> GenerateAuthTokenFromProfileAsync(string profileName, RegionEndpoint region)
    {
        var chain = new CredentialProfileStoreChain();

        if (chain.TryGetAWSCredentials(profileName, out var awsCredentials))
        {
            return GenerateAuthTokenFromCredentialsProvider(() => awsCredentials, region).AsTask();
        }

        throw new ArgumentException($"Could not find credentials using profile {profileName}");
    }

#endregion GenerateAuthTokenFromProfile

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using client provided AWS credentials.
    /// <remarks> </remarks>
    /// </summary>
    /// <param name="credentialsProvider">A Function which returns AWSCredentials to be used for signing the request</param>
    /// <param name="region">Region of the MSK cluster</param>
    /// <param name="useAsync">Specifies to use async model</param>
    /// <returns> A tuple containing Auth token in string format and it's expiry time </returns>
    public async ValueTask<(string, long)> GenerateAuthTokenFromCredentialsProvider(Func<AWSCredentials> credentialsProvider, RegionEndpoint region, bool useAsync = true)
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

        TimeSpan ttl = ExpiryDuration;
        if (credentials.Expiration is not null) {
            // Calculate actual TTL for credential
            TimeSpan ttlCredential = credentials.Expiration.Value - _timeProvider.Invoke();
            // Only use TTL for credential if it's less than the prior TTL to cap token lifetime
            if (ttlCredential < ttl) {
                ttl = ttlCredential;
                _logger.LogDebug("Lifetime of token is shorter than default of 15 minutes: {lifetime}s", ttlCredential.TotalSeconds.ToString(CultureInfo.InvariantCulture));
            }
        }

        var immutableCredentials = useAsync ? await credentials.GetCredentialsAsync() : credentials.GetCredentials();

        _logger.LogDebug("Generating auth token using credentials with access key id: {accessKey}", immutableCredentials.AccessKey);

        var authTokenRequest = new GenerateMskAuthTokenRequest();
        IRequest request = new DefaultRequest(authTokenRequest, ServiceName);

        request.UseQueryString = true;
        request.HttpMethod = HttpMethod;
        request.Parameters.Add(XAmzExpires, ttl.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        request.Parameters.Add(ActionKey, ActionValue);
        var hostName = string.Format(HostnameStringFormat, region.SystemName);
        request.Endpoint = new UriBuilder(Scheme, hostName).Uri;

        if (immutableCredentials.UseToken)
        {
            request.Parameters[XAmzSecurityToken] = immutableCredentials.Token;
        }

        var signingResult = AWS4PreSignedUrlSigner.SignRequest(request, null, new RequestMetrics(),
            immutableCredentials.AccessKey,
            immutableCredentials.SecretKey, ServiceName, region.SystemName);

        var authorization = signingResult.ForQueryParameters;
        var url = AmazonServiceClient.ComposeUrl(request);

        var authTokenString = $"{url.AbsoluteUri}&{GetUserAgent()}&{authorization}";

        var byteArray = Encoding.UTF8.GetBytes(authTokenString);

        var expiryMs = new DateTimeOffset(signingResult.DateTime.Add(ttl)).ToUnixTimeSeconds() * 1000;
        return (Convert.ToBase64String(byteArray).Replace('+', '-').Replace('/', '_').TrimEnd('='), expiryMs);
    }

    private static string GetUserAgent() => $"User-Agent=aws-msk-iam-sasl-signer-net-{SignerVersion.CurrentVersion}";

    /// <summary>
    ///     Helper method to log the user credentials
    /// </summary>
    /// <param name="credentials"></param>
    /// <param name="region"></param>
    /// <param name="awsDebugCreds"></param>
    /// <returns></returns>
    private async Task LogCredentialsIdentity(AWSCredentials credentials, RegionEndpoint region, bool awsDebugCreds)
    {
        if (awsDebugCreds && _logger.IsEnabled(LogLevel.Debug))
        {
            AmazonSecurityTokenServiceClient stsDebugClient = new(credentials, region);
            var response = await stsDebugClient.GetCallerIdentityAsync(new GetCallerIdentityRequest());

            _logger.LogDebug("Credentials Identity: UserId: {user}, Account: {account}, Arn: {arn}", response.UserId, response.Account, response.Arn);
        }
    }
}
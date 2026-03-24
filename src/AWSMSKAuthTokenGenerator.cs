// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AWS.MSK.Auth;

/// <summary>
/// Generates pre-signed authentication tokens for AWS MSK clusters using IAM credentials.
/// This class is thread-safe and designed to be used as a long-lived singleton.
/// </summary>
public sealed class AWSMSKAuthTokenGenerator
{
    private const int MinTtlSeconds = 1;
    private const int MaxTtlSeconds = 604800; // 7 days — AWS SigV4 maximum
    private const string ServiceName = "kafka-cluster";
    private const string HttpMethod = "GET";
    private const string Scheme = "https";
    private const string ActionKey = "Action";
    private const string ActionValue = "kafka-cluster:Connect";
    private const string XAmzExpires = "X-Amz-Expires";
    private const string XAmzSecurityToken = "X-Amz-Security-Token";
    private const string HostnameStringFormat = "kafka.{0}.amazonaws.com";
    private const string DefaultSession = "MSKSASLDefaultSession";

    private static readonly string UserAgentString = $"User-Agent={Uri.EscapeDataString($"aws-msk-iam-sasl-signer-net-{SignerVersion.CurrentVersion}")}";

    private TimeSpan _expiryDuration = TimeSpan.FromSeconds(900);

    /// <summary>
    /// The duration for which the generated auth token is valid.
    /// Must be between 1 second and 604800 seconds (7 days).
    /// Default: 900 seconds (15 minutes).
    /// </summary>
    public TimeSpan ExpiryDuration
    {
        get => _expiryDuration;
        set
        {
            if (value.TotalSeconds < MinTtlSeconds || value.TotalSeconds > MaxTtlSeconds)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(ExpiryDuration),
                    $"ExpiryDuration must be between {MinTtlSeconds}s and {MaxTtlSeconds}s, but was {value.TotalSeconds}s.");
            }

            _expiryDuration = value;
        }
    }

    private AmazonSecurityTokenServiceClient? _stsClient;
    private RegionEndpoint? _stsClientRegion;
    private readonly object _stsClientLock = new();
    private readonly ILogger<AWSMSKAuthTokenGenerator> _logger;
    private readonly Func<DateTime> _timeProvider;
    private readonly bool _stsClientProvided;

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
        _stsClientProvided = stsClient is not null;
        _stsClient = stsClient;
        _stsClientRegion = stsClient?.Config?.RegionEndpoint;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<AWSMSKAuthTokenGenerator>();
        _timeProvider = timeProvider ?? (static () => DateTime.UtcNow);
    }

    /// <summary>
    /// AWS4PreSignedUrlSigner is built around operation request objects.
    /// This request type will only be used to generate the signed token.
    /// It will never be used to make an actual request to a cluster.
    /// </summary>
    private sealed class GenerateMskAuthTokenRequest : AmazonWebServiceRequest
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
    ///     Note that this only works when LogLevel for logger is configured as Debug.
    ///     Using this in Production is discouraged as it creates a new STS client on every invocation.</param>
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    public (string Token, long ExpiryMs) GenerateAuthToken(RegionEndpoint region, bool awsDebugCreds = false)
    {
        AWSCredentials credentials = DefaultAWSCredentialsIdentityResolver.GetCredentials();

        LogCredentialsIdentity(credentials, region, awsDebugCreds).ConfigureAwait(false).GetAwaiter().GetResult();

        return GenerateAuthTokenFromCredentialsProvider(() => credentials, region, false).ConfigureAwait(false).GetAwaiter().GetResult();
    }

    /// <inheritdoc cref="GenerateAuthToken"/>
    public async Task<(string Token, long ExpiryMs)> GenerateAuthTokenAsync(RegionEndpoint region, bool awsDebugCreds = false)
    {
        AWSCredentials credentials = await DefaultAWSCredentialsIdentityResolver.GetCredentialsAsync().ConfigureAwait(false);

        await LogCredentialsIdentity(credentials, region, awsDebugCreds).ConfigureAwait(false);

        return await GenerateAuthTokenFromCredentialsProvider(() => credentials, region).ConfigureAwait(false);
    }

    #endregion GenerateAuthToken

    #region GenerateAuthTokenFromRole

    private AmazonSecurityTokenServiceClient GetStsClient(RegionEndpoint region)
    {
        // If the STS client was provided via the constructor, always use it
        if (_stsClientProvided)
        {
            return _stsClient!;
        }

        if (_stsClient is null || _stsClientRegion != region)
        {
            lock (_stsClientLock)
            {
                if (_stsClient is null || _stsClientRegion != region)
                {
                    _stsClient?.Dispose();
                    _stsClient = new AmazonSecurityTokenServiceClient(region);
                    _stsClientRegion = region;
                }
            }
        }

        return _stsClient!;
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
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    public (string Token, long ExpiryMs) GenerateAuthTokenFromRole(RegionEndpoint region, string roleArn, string sessionName = DefaultSession)
    {
        var assumeRoleReq = new AssumeRoleRequest
        {
            RoleSessionName = sessionName,
            RoleArn = roleArn
        };

        var assumeRoleResponse = GetStsClient(region).AssumeRoleAsync(assumeRoleReq)
            .ConfigureAwait(false).GetAwaiter().GetResult();

        var stsCredentials = assumeRoleResponse.Credentials;

        return GenerateAuthTokenFromCredentialsProvider(
                () => new SessionAWSCredentials(stsCredentials.AccessKeyId, stsCredentials.SecretAccessKey,
                    stsCredentials.SessionToken), region, false)
            .ConfigureAwait(false).GetAwaiter().GetResult();
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
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    public async Task<(string Token, long ExpiryMs)> GenerateAuthTokenFromRoleAsync(RegionEndpoint region, string roleArn, string sessionName = DefaultSession)
    {
        var assumeRoleReq = new AssumeRoleRequest
        {
            RoleSessionName = sessionName,
            RoleArn = roleArn
        };

        var assumeRoleResponse = await GetStsClient(region).AssumeRoleAsync(assumeRoleReq).ConfigureAwait(false);

        var stsCredentials = assumeRoleResponse.Credentials;

        return await GenerateAuthTokenFromCredentialsProvider(
            () => new SessionAWSCredentials(stsCredentials.AccessKeyId, stsCredentials.SecretAccessKey,
                stsCredentials.SessionToken), region).ConfigureAwait(false);
    }

    #endregion GenerateAuthTokenFromRole

    #region GenerateAuthTokenFromProfile

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using an IAM Profile.
    /// <remarks>
    /// This method generates an auth token using an IAM Profile.
    /// </remarks>
    /// </summary>
    /// <param name="profileName">AWS Credentials to sign the request will be fetched from this profile.</param>
    /// <param name="region">Region of the MSK cluster.</param>
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    public (string Token, long ExpiryMs) GenerateAuthTokenFromProfile(string profileName, RegionEndpoint region)
    {
        var chain = new CredentialProfileStoreChain();

        if (chain.TryGetAWSCredentials(profileName, out var awsCredentials))
        {
            return GenerateAuthTokenFromCredentialsProvider(() => awsCredentials, region, false).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        throw new ArgumentException($"Could not find credentials using profile {profileName}");
    }

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using an IAM Profile.
    /// <remarks>
    /// This method generates an auth token using an IAM Profile.
    /// </remarks>
    /// </summary>
    /// <param name="profileName">AWS Credentials to sign the request will be fetched from this profile.</param>
    /// <param name="region">Region of the MSK cluster.</param>
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    public async Task<(string Token, long ExpiryMs)> GenerateAuthTokenFromProfileAsync(string profileName, RegionEndpoint region)
    {
        var chain = new CredentialProfileStoreChain();

        if (chain.TryGetAWSCredentials(profileName, out var awsCredentials))
        {
            return await GenerateAuthTokenFromCredentialsProvider(() => awsCredentials, region).ConfigureAwait(false);
        }

        throw new ArgumentException($"Could not find credentials using profile {profileName}");
    }

    #endregion GenerateAuthTokenFromProfile

    /// <summary>
    /// Generate a token for IAM authentication to an MSK cluster using client-provided AWS credentials.
    /// </summary>
    /// <param name="credentialsProvider">A function that returns <see cref="AWSCredentials"/> to be used for signing the request.</param>
    /// <param name="region">Region of the MSK cluster.</param>
    /// <param name="useAsync">When <c>true</c>, uses async credential resolution; when <c>false</c>, uses synchronous.</param>
    /// <returns>A tuple containing the auth token string and its expiry time in Unix milliseconds.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="credentialsProvider"/>, <paramref name="region"/>, or the returned credentials are null.</exception>
    public async ValueTask<(string Token, long ExpiryMs)> GenerateAuthTokenFromCredentialsProvider(Func<AWSCredentials> credentialsProvider, RegionEndpoint region, bool useAsync = true)
    {
        if (credentialsProvider is null)
        {
            throw new ArgumentNullException(nameof(credentialsProvider));
        }

        if (region is null)
        {
            throw new ArgumentNullException(nameof(region));
        }

        AWSCredentials credentials = credentialsProvider();

        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        // IMPORTANT: Resolve immutable credentials FIRST, before computing TTL.
        // GetCredentialsAsync() may trigger a background refresh of expiring credentials
        // (especially in AWS SDK v4 with ECS/EC2 instance roles). If we computed TTL
        // before resolving, we'd read the OLD expiration (possibly near-zero or negative)
        // but then sign with the FRESH credentials — producing a token that expires immediately.
        var immutableCredentials = useAsync
            ? await credentials.GetCredentialsAsync().ConfigureAwait(false)
            : credentials.GetCredentials();

        // Now compute TTL from the (possibly refreshed) credential state
        TimeSpan ttl = GetTtl(credentials);
        var ttlSeconds = (int)ttl.TotalSeconds;

        _logger.LogDebug("Generating auth token using credentials with access key id: {AccessKey}", immutableCredentials.AccessKey);

        IRequest request = new DefaultRequest(new GenerateMskAuthTokenRequest(), ServiceName)
        {
            UseQueryString = true,
            HttpMethod = HttpMethod,
            Endpoint = new UriBuilder(Scheme, string.Format(CultureInfo.InvariantCulture, HostnameStringFormat, region.SystemName)).Uri
        };

        request.Parameters.Add(XAmzExpires, ttlSeconds.ToString(CultureInfo.InvariantCulture));
        request.Parameters.Add(ActionKey, ActionValue);

        if (immutableCredentials.UseToken)
        {
            request.Parameters[XAmzSecurityToken] = immutableCredentials.Token;
        }

        var signingResult = AWS4PreSignedUrlSigner.SignRequest(
            request, null, new RequestMetrics(),
            immutableCredentials.AccessKey, immutableCredentials.SecretKey,
            ServiceName, region.SystemName);

        var url = AmazonServiceClient.ComposeUrl(request);
        var authTokenString = string.Concat(url.AbsoluteUri, "&", UserAgentString, "&", signingResult.ForQueryParameters);

        var expiryMs = (new DateTimeOffset(signingResult.DateTime).ToUnixTimeSeconds() + ttlSeconds) * 1000;
        return (Base64UrlEncode(authTokenString), expiryMs);
    }

    /// <summary>
    /// Encodes a string as base64url (RFC 4648 §5) without padding.
    /// </summary>
    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private TimeSpan GetTtl(AWSCredentials credentials)
    {
        var expiryDuration = ExpiryDuration;
        TimeSpan ttl = expiryDuration;

        if (credentials.Expiration is null)
        {
            return ttl;
        }

        // Calculate actual TTL for credential
        TimeSpan ttlCredential = credentials.Expiration.Value - _timeProvider.Invoke();

        // Guard against expired or near-expired credentials producing a zero/negative TTL.
        // This can happen when credentials are at the very edge of their refresh window.
        if (ttlCredential.TotalSeconds < MinTtlSeconds)
        {
            _logger.LogWarning(
                "Credential TTL is non-positive ({ttl}s). Credentials may have already expired. " +
                "Clamping to {min}s minimum — token may still be rejected by the broker.",
                ttlCredential.TotalSeconds.ToString(CultureInfo.InvariantCulture),
                MinTtlSeconds.ToString(CultureInfo.InvariantCulture));
            return TimeSpan.FromSeconds(MinTtlSeconds);
        }

        // Only use TTL for credential if it's less than the prior TTL to cap token lifetime
        if (ttlCredential >= ttl)
        {
            return ttl;
        }

        ttl = ttlCredential;
        _logger.LogDebug("Lifetime of token is shorter than set value of {configuredLifetime}s: {lifetime}s",
            expiryDuration.TotalSeconds.ToString(CultureInfo.InvariantCulture),
            ttl.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        return ttl;
    }

    /// <summary>
    /// Logs the caller identity for debugging purposes.
    /// Only active when <paramref name="awsDebugCreds"/> is true and Debug logging is enabled.
    /// </summary>
    private async Task LogCredentialsIdentity(AWSCredentials credentials, RegionEndpoint region, bool awsDebugCreds)
    {
        if (awsDebugCreds && _logger.IsEnabled(LogLevel.Debug))
        {
            using AmazonSecurityTokenServiceClient stsDebugClient = new(credentials, region);
            var response = await stsDebugClient.GetCallerIdentityAsync(new GetCallerIdentityRequest()).ConfigureAwait(false);

            _logger.LogDebug("Credentials Identity: UserId: {UserId}, Account: {Account}, Arn: {Arn}", response.UserId, response.Account, response.Arn);
        }
    }
}

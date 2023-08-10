// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

using Amazon;
using Amazon.Runtime;
using System;
using Moq;
using System.Globalization;
using System.Text;
using System.Web;
using System.Text.RegularExpressions;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Amazon.Runtime.Credentials;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Logging.Abstractions;

namespace AWS.MSK.Auth.Tests;

public class AWSMSKAuthTokenGeneratorTest
{
    private static List<string> SIGV4_KEYS = new List<string>() { "Action", "X-Amz-Expires", "X-Amz-Algorithm", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Credential", "User-Agent", "X-Amz-Signature", "X-Amz-Security-Token" };

    private static AWSCredentials sessionCredentials = new SessionAWSCredentials("accessKey", "secretKey", "sessionToken");

    [Fact]
    public static void GenerateAuthToken_TestNoCredentials()
    {
        List<FallbackCredentialsFactory.CredentialsGenerator> originalFallbackList = FallbackCredentialsFactory.CredentialsGenerators;
        
        AWSMSKAuthTokenGenerator authTokenGenerator = new AWSMSKAuthTokenGenerator(null, NullLoggerFactory.Instance);
  
        try
        {
            FallbackCredentialsFactory.Reset();
            FallbackCredentialsFactory.CredentialsGenerators = new List<FallbackCredentialsFactory.CredentialsGenerator>()
            {
                () => { return sessionCredentials; }
            };

            (String token, long expiryMs) = authTokenGenerator.GenerateAuthToken(RegionEndpoint.USEast1);
            validateTokenSignature(token, expiryMs  );
        }
        finally
        {
            FallbackCredentialsFactory.Reset();
            FallbackCredentialsFactory.CredentialsGenerators = originalFallbackList;
        }
    }

    [Fact]
    public static void GenerateAuthToken_TestInjectedCredentials()
    {
        AWSMSKAuthTokenGenerator authTokenGenerator = new AWSMSKAuthTokenGenerator();

        var credentialsProviderMock = new Moq.Mock<Func<AWSCredentials>>();
        credentialsProviderMock.Setup(provider => provider.Invoke()).Returns(sessionCredentials);
        (String token, long expiryMs) = authTokenGenerator.GenerateAuthTokenFromCredentialsProvider(credentialsProviderMock.Object, RegionEndpoint.USEast1);

        validateTokenSignature(token, expiryMs);
    }


    [Fact]
    public async static Task GenerateAuthToken_TestStsRoles()
    {
       
        AssumeRoleResponse assumeRoleResponse = new AssumeRoleResponse();
        assumeRoleResponse.Credentials = new Credentials("accessKey", "secretKey", "sessionToken", DateTime.Now);

        var stsClientMock = new Moq.Mock<AmazonSecurityTokenServiceClient>();

        stsClientMock.Setup(m => m.AssumeRoleAsync(It.Is<AssumeRoleRequest>(r=> r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole" && r.RoleSessionName == "mySession"), default)).Returns(Task.FromResult(assumeRoleResponse));

        AWSMSKAuthTokenGenerator authTokenGenerator = new AWSMSKAuthTokenGenerator(stsClientMock.Object, null);

        (String token, long expiryMs) = await authTokenGenerator.GenerateAuthTokenFromRoleAsync(RegionEndpoint.USEast1, "arn:aws:iam::123456789101:role/MSKRole", "mySession");

        validateTokenSignature(token, expiryMs);
     
    }


    [Fact]
    public static void GenerateAuthToken_NullCredentials_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(null, RegionEndpoint.USEast1));
    }

    [Fact]
    public static void GenerateAuthToken_NullRegion_ThrowsArgumentException()
    {
        var credentialsProviderMock = new Moq.Mock<Func<AWSCredentials>>();
        credentialsProviderMock.Setup(proivder => proivder.Invoke()).Returns(sessionCredentials);

        Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(credentialsProviderMock.Object, null));
    }

    [Fact]
    public static void GenerateAuthToken_NullCredentials_ThrowsArgumentNullException()
    {
        var credentialsProviderMock = new Moq.Mock<Func<AWSCredentials>>();

        AWSCredentials credentials = null;

        credentialsProviderMock.Setup(proivder => proivder.Invoke()).Returns(credentials);

        Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(credentialsProviderMock.Object, null));
    }


    private static void validateTokenSignature(string token, long expiryMs)
    {
        byte[] decoded = Decode(token);

        var parsedUrl = new Uri(Encoding.UTF8.GetString(decoded, 0, decoded.Length));
        var queryParams = HttpUtility.ParseQueryString(parsedUrl.Query);
        string[] credentialsTokens = queryParams["X-Amz-Credential"].Split('/');

        Assert.Equal("kafka.us-east-1.amazonaws.com", parsedUrl.Host);
        Assert.Equal("kafka-cluster:Connect", queryParams["Action"]);
        Assert.Equal("host", queryParams["X-Amz-SignedHeaders"]);
        Assert.Equal("AWS4-HMAC-SHA256", queryParams["X-Amz-Algorithm"]);
        Assert.Equal("900", queryParams["X-Amz-Expires"]);
        Assert.Equal("accessKey", credentialsTokens[0]);
        Assert.Equal("us-east-1", credentialsTokens[2]);
        Assert.Equal("kafka-cluster", credentialsTokens[3]);
        Assert.Equal("aws4_request", credentialsTokens[4]);
        Assert.Equal("sessionToken", queryParams["X-Amz-Security-Token"]);
        Assert.Equal("aws-msk-iam-sasl-signer-net-"+SignerVersion.CurrentVersion, queryParams["User-Agent"]);
        Assert.True(Regex.IsMatch(queryParams["X-Amz-Date"], "(\\d{4})(\\d{2})(\\d{2})T(\\d{2})(\\d{2})(\\d{2})Z", RegexOptions.None));
        Assert.All(queryParams.AllKeys, key => SIGV4_KEYS.Contains(key));

        long expectedExpiryMs = new DateTimeOffset(DateTime.ParseExact(queryParams["X-Amz-Date"], "yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture).Add(TimeSpan.FromSeconds(900))).ToUnixTimeMilliseconds();
        Assert.Equal(expectedExpiryMs, expiryMs);
    }
    private static byte[] Decode(string encoded)
    {
        List<char> list = new List<char>(encoded.ToCharArray());
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i] == '_')
            {
                list[i] = '/';
            }
            else if (list[i] == '-')
            {
                list[i] = '+';
            }
        }
        switch (encoded.Length % 4)
        {
            case 2:
                list.AddRange("==");
                break;
            case 3:
                list.Add('=');
                break;
        }
        char[] array = list.ToArray();
        return Convert.FromBase64CharArray(array, 0, array.Length);
    }
}

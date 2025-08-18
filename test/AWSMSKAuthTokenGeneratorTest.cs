using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Moq;

namespace AWS.MSK.Auth.Test
{
    public class AwsmskAuthTokenGeneratorTest
    {
        private static readonly HashSet<string> Sigv4Keys =
        [
            "Action", "X-Amz-Expires", "X-Amz-Algorithm", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Credential",
            "User-Agent", "X-Amz-Signature", "X-Amz-Security-Token"
        ];

        private static readonly AWSCredentials SessionCredentials = new SessionAWSCredentials("accessKey", "secretKey", "sessionToken");

        [Fact]
        public void GenerateAuthToken_TestNoCredentials()
        {
            var originalFallbackList = AWSConfigs.AWSCredentialsGenerators;

            try
            {
                AWSConfigs.AWSCredentialsGenerators = [() => SessionCredentials];

                (string token, long expiryMs) = new AWSMSKAuthTokenGenerator().GenerateAuthToken(RegionEndpoint.USEast1);
                ValidateTokenSignature(token, expiryMs);
            }
            finally
            {
                AWSConfigs.AWSCredentialsGenerators = originalFallbackList;
            }
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentials()
        {
            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(() => SessionCredentials, RegionEndpoint.USEast1,false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs);
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentialsWithSoonExpiration()
        {
            DateTime now = DateTime.UtcNow;
            TimeSpan ttl = TimeSpan.FromMinutes(5);

            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator(timeProvider: () => now)
                .GenerateAuthTokenFromCredentialsProvider(() => new SessionAWSCredentials("accessKey", "secretKey", "sessionToken") { Expiration = now + ttl }, RegionEndpoint.USEast1,
                    false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs, ttl);
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentialsWithLongExpiration()
        {
            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator()
                .GenerateAuthTokenFromCredentialsProvider(
                    () => new SessionAWSCredentials("accessKey", "secretKey", "sessionToken") { Expiration = DateTime.UtcNow.AddHours(6) },
                    RegionEndpoint.USEast1, false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs);
        }

        [Fact]
        public void GenerateAuthToken_TestNoCredentials_CustomExpiryDuration()
        {
            var originalFallbackList = AWSConfigs.AWSCredentialsGenerators;

            try
            {
                AWSConfigs.AWSCredentialsGenerators = [() => SessionCredentials];

                TimeSpan expiryDuration = TimeSpan.FromMinutes(20);

                (string token, long expiryMs) = new AWSMSKAuthTokenGenerator { ExpiryDuration = expiryDuration }.GenerateAuthToken(RegionEndpoint.USEast1);
                ValidateTokenSignature(token, expiryMs, expiryDuration);
            }
            finally
            {
                AWSConfigs.AWSCredentialsGenerators = originalFallbackList;
            }
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentials_CustomExpiryDuration()
        {
            TimeSpan expiryDuration = TimeSpan.FromMinutes(20);

            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator { ExpiryDuration = expiryDuration }.GenerateAuthTokenFromCredentialsProvider(() => SessionCredentials, RegionEndpoint.USEast1,false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs, expiryDuration);
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentialsWithSoonExpiration_CustomExpiryDuration()
        {
            DateTime now = DateTime.UtcNow;
            TimeSpan ttl = TimeSpan.FromMinutes(5);

            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator(timeProvider: () => now) { ExpiryDuration = TimeSpan.FromMinutes(20) }
                .GenerateAuthTokenFromCredentialsProvider(() => new SessionAWSCredentials("accessKey", "secretKey", "sessionToken") { Expiration = now + ttl }, RegionEndpoint.USEast1,
                    false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs, ttl);
        }

        [Fact]
        public void GenerateAuthToken_TestInjectedCredentialsWithLongExpiration_CustomExpiryDuration()
        {
            TimeSpan expiryDuration = TimeSpan.FromMinutes(20);

            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator { ExpiryDuration = expiryDuration }
                .GenerateAuthTokenFromCredentialsProvider(
                    () => new SessionAWSCredentials("accessKey", "secretKey", "sessionToken") { Expiration = DateTime.UtcNow.AddHours(6) },
                    RegionEndpoint.USEast1, false).GetAwaiter().GetResult();

            ValidateTokenSignature(token, expiryMs, expiryDuration);
        }

        [Fact]
        public void GenerateAuthToken_TestStsRoles()
        {
            var assumeRoleResponse = new AssumeRoleResponse
            {
                Credentials = new Credentials("accessKey", "secretKey", "sessionToken", DateTime.UtcNow)
            };

            RegionEndpoint region = RegionEndpoint.USEast1;

            var stsClientMock = new Mock<AmazonSecurityTokenServiceClient>(region);
            stsClientMock.Setup(m => m.AssumeRoleAsync(It.Is<AssumeRoleRequest>(r => r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole" && r.RoleSessionName == "mySession"), CancellationToken.None)).Returns(Task.FromResult(assumeRoleResponse));

            (var token, long expiryMs) = new AWSMSKAuthTokenGenerator(stsClientMock.Object).GenerateAuthTokenFromRole(region, "arn:aws:iam::123456789101:role/MSKRole", "mySession");

            ValidateTokenSignature(token, expiryMs);
        }

        [Fact]
        public void GenerateAuthToken_VerifyStsClientAlwaysUsedWhenSupplied()
        {
            var assumeRoleResponse = new AssumeRoleResponse
            {
                Credentials = new Credentials("accessKey", "secretKey", "sessionToken", DateTime.UtcNow)
            };

            var stsClientMock = new Mock<AmazonSecurityTokenServiceClient>(RegionEndpoint.USEast1);
            stsClientMock
                .Setup(m => m.AssumeRoleAsync(
                    It.Is<AssumeRoleRequest>(r =>
                        r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole" && r.RoleSessionName == "mySession"),
                    CancellationToken.None)).Returns(Task.FromResult(assumeRoleResponse));
            stsClientMock
                .Setup(m => m.AssumeRoleAsync(
                    It.Is<AssumeRoleRequest>(r =>
                        r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole2" && r.RoleSessionName == "mySession2"),
                    CancellationToken.None)).Returns(Task.FromResult(assumeRoleResponse));

            var awsMskAuthTokenGenerator = new AWSMSKAuthTokenGenerator(stsClientMock.Object);

            awsMskAuthTokenGenerator.GenerateAuthTokenFromRole(RegionEndpoint.USEast1,
                "arn:aws:iam::123456789101:role/MSKRole", "mySession");
            stsClientMock.Verify(m =>
                m.AssumeRoleAsync(
                    It.Is<AssumeRoleRequest>(r =>
                        r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole" && r.RoleSessionName == "mySession"),
                    CancellationToken.None));

            awsMskAuthTokenGenerator.GenerateAuthTokenFromRole(RegionEndpoint.USEast1,
                "arn:aws:iam::123456789101:role/MSKRole2", "mySession2");
            stsClientMock.Verify(m =>
                m.AssumeRoleAsync(
                    It.Is<AssumeRoleRequest>(r =>
                        r.RoleArn == "arn:aws:iam::123456789101:role/MSKRole2" && r.RoleSessionName == "mySession2"),
                    CancellationToken.None));
        }

        [Fact]
        public static void GenerateAuthToken_NullCredentials_ThrowsArgumentException()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(null!, RegionEndpoint.USEast1,false).GetAwaiter().GetResult());
            Assert.Contains("credentialsProvider", exception.Message);
        }

        [Fact]
        public static void GenerateAuthToken_NullRegion_ThrowsArgumentException()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(() => SessionCredentials, null!, false).GetAwaiter().GetResult());
            Assert.Contains("region", exception.Message);
        }

        [Fact]
        public static void GenerateAuthToken_NullCredentials_ThrowsArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => new AWSMSKAuthTokenGenerator().GenerateAuthTokenFromCredentialsProvider(() => null!, RegionEndpoint.USEast1, false).GetAwaiter().GetResult());
            Assert.Contains("credentials", exception.Message);
        }

        private static void ValidateTokenSignature(string token, long expiryMs, TimeSpan? expectedTtl = null)
        {
            byte[] decoded = Decode(token);

            var parsedUrl = new Uri(Encoding.UTF8.GetString(decoded, 0, decoded.Length));
            var queryParams = HttpUtility.ParseQueryString(parsedUrl.Query);
            string[] credentialsTokens = queryParams["X-Amz-Credential"]!.Split('/');

            Assert.Equal("kafka.us-east-1.amazonaws.com", parsedUrl.Host);
            Assert.Equal("kafka-cluster:Connect", queryParams["Action"]);
            Assert.Equal("host", queryParams["X-Amz-SignedHeaders"]);
            Assert.Equal("AWS4-HMAC-SHA256", queryParams["X-Amz-Algorithm"]);
            Assert.Equal(expectedTtl is not null ? expectedTtl.Value.TotalSeconds.ToString(CultureInfo.InvariantCulture) : "900", queryParams["X-Amz-Expires"]);
            Assert.Equal("accessKey", credentialsTokens[0]);
            Assert.Equal("us-east-1", credentialsTokens[2]);
            Assert.Equal("kafka-cluster", credentialsTokens[3]);
            Assert.Equal("aws4_request", credentialsTokens[4]);
            Assert.Equal("sessionToken", queryParams["X-Amz-Security-Token"]);
            Assert.Equal("aws-msk-iam-sasl-signer-net-" + SignerVersion.CurrentVersion, queryParams["User-Agent"]);
            Assert.True(Regex.IsMatch(queryParams["X-Amz-Date"]!, "(\\d{4})(\\d{2})(\\d{2})T(\\d{2})(\\d{2})(\\d{2})Z", RegexOptions.None));
            Assert.All(queryParams.AllKeys, key => Assert.Contains(key!, Sigv4Keys));

            long expectedExpiryMs = new DateTimeOffset(DateTime.ParseExact(queryParams["X-Amz-Date"]!, "yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture).Add(expectedTtl ?? TimeSpan.FromSeconds(900))).ToUnixTimeMilliseconds();
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
}

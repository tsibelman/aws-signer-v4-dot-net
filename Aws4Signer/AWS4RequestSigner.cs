using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Aws4RequestSigner
{
    public class AWS4RequestSigner:IDisposable
    {
        private readonly string _accessKey;
        private readonly string _secretKey;
        private readonly SHA256 _sha256;
        private const string ALGORITHM = "AWS4-HMAC-SHA256";
        private const string EMPTY_STRING_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        public AWS4RequestSigner(string accessKey, string secretKey)
        {

            if (string.IsNullOrEmpty(accessKey))
            {
                throw new ArgumentOutOfRangeException(nameof(accessKey), accessKey, "Not a valid access_key.");
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentOutOfRangeException(nameof(secretKey), secretKey, "Not a valid secret_key.");
            }

            _accessKey = accessKey;
            _secretKey = secretKey;
            _sha256 = SHA256.Create();
        }

        private string Hash(byte[] bytesToHash)
        {
            var result = _sha256.ComputeHash(bytesToHash);
            return ToHexString(result);
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            var hashAlgorithm = new HMACSHA256(key);

            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            var kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            var kDate = HmacSha256(kSecret, dateStamp);
            var kRegion = HmacSha256(kDate, regionName);
            var kService = HmacSha256(kRegion, serviceName);
            var kSigning = HmacSha256(kService, "aws4_request");
            return kSigning;
        }

        private static string ToHexString(IReadOnlyCollection<byte> array)
        {
            var hex = new StringBuilder(array.Count * 2);
            foreach (var b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        public async Task<HttpRequestMessage> Sign(HttpRequestMessage request, string service, string region, TimeSpan? timeOffset = null)
        {
            if (string.IsNullOrEmpty(service))
            {
                throw new ArgumentOutOfRangeException(nameof(service), service, "Not a valid service.");
            }

            if (string.IsNullOrEmpty(region))
            {
                throw new ArgumentOutOfRangeException(nameof(region), region, "Not a valid region.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.Headers.Host == null)
            {
                request.Headers.Host = request.RequestUri.Host;
            }
            
            var content = new byte[0];
            if (request.Content != null) {
                content = await request.Content.ReadAsByteArrayAsync();
            }
            
            var payloadHash = EMPTY_STRING_HASH;
            if (content.Length != 0) {
                payloadHash = Hash(content);
            }

            if (request.Headers.Contains("x-amz-content-sha256") == false)
                request.Headers.Add("x-amz-content-sha256", payloadHash);
            
            var t = DateTimeOffset.UtcNow;
            if (timeOffset.HasValue)
                t = t.Add(timeOffset.Value);
            var amzDate = t.ToString("yyyyMMddTHHmmssZ");
            request.Headers.Add("x-amz-date", amzDate);
            var dateStamp = t.ToString("yyyyMMdd");

            var canonicalRequest = new StringBuilder();
            canonicalRequest.Append(request.Method + "\n");
           
            canonicalRequest.Append(string.Join("/", request.RequestUri.AbsolutePath.Split('/').Select(Uri.EscapeDataString)) + "\n");

            var canonicalQueryParams = GetCanonicalQueryParams(request);

            canonicalRequest.Append(canonicalQueryParams + "\n");

            var signedHeadersList = new List<string>();

            foreach (var header in request.Headers.OrderBy(a => a.Key.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase))
            {
                canonicalRequest.Append(header.Key.ToLowerInvariant());
                canonicalRequest.Append(":");
                canonicalRequest.Append(string.Join(",", header.Value.Select(s => s.Trim())));
                canonicalRequest.Append("\n");
                signedHeadersList.Add(header.Key.ToLowerInvariant());
            }

            canonicalRequest.Append("\n");

            var signedHeaders = string.Join(";", signedHeadersList);

            canonicalRequest.Append(signedHeaders + "\n");
            canonicalRequest.Append(payloadHash);
            
            var credentialScope = $"{dateStamp }/{region}/{service}/aws4_request";
                       
            var stringToSign = $"{ALGORITHM}\n{amzDate}\n{credentialScope}\n" + Hash(Encoding.UTF8.GetBytes(canonicalRequest.ToString()));

            var signingKey = GetSignatureKey(_secretKey, dateStamp , region, service);
            var signature = ToHexString(HmacSha256(signingKey, stringToSign));
            
            request.Headers.TryAddWithoutValidation("Authorization", $"{ALGORITHM} Credential={_accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}");

            return request;
        }

        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var values = new SortedDictionary<string, IEnumerable<string>>();

            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            foreach (var key in querystring.AllKeys)
            {
                if (key == null)//Handles keys without values
                {
                    values.Add(Uri.EscapeDataString(querystring[key]), new[] { $"{Uri.EscapeDataString(querystring[key])}=" });
                }
                else
                {
                    // Handles multiple values per query parameter
                    var queryValues = querystring[key].Split(',')
                        // Order by value alphanumerically (required for correct canonical string)
                        .OrderBy(v => v)
                        // Query params must be escaped in upper case (i.e. "%2C", not "%2c").
                        .Select(v => $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(v)}");

                    values.Add(Uri.EscapeDataString(key), queryValues);
                }
            }

            var queryParams = values.SelectMany(a => a.Value);
            var canonicalQueryParams = string.Join("&", queryParams);
            return canonicalQueryParams;
        }

        public void Dispose()
        {
            _sha256.Dispose();
        }
    }
}
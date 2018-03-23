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
    public class AWS4RequestSigner
    {
        private readonly string _access_key;
        private readonly string _secret_key;
        private readonly string _token;
        private readonly SHA256 _sha256;
        private const string algorithm = "AWS4-HMAC-SHA256";

        public AWS4RequestSigner(string accessKey, string secretKey, string token = null)
        {

            if (string.IsNullOrEmpty(accessKey))
            {
                throw new ArgumentOutOfRangeException(nameof(accessKey), accessKey, "Not a valid access_key.");
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentOutOfRangeException(nameof(secretKey), secretKey, "Not a valid secret_key.");
            }

            _access_key = accessKey;
            _secret_key = secretKey;
            _token = token;
            _sha256 = SHA256.Create();
        }

        private string Hash(string stringToHash)
        {
            var result = _sha256.ComputeHash(Encoding.UTF8.GetBytes(stringToHash));
            return ToHexString(result);
        }

        private static byte[] HmacSHA256(byte[] key, string data)
        {
            var hashAlgorithm = new HMACSHA256(key);

            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            byte[] kDate = HmacSHA256(kSecret, dateStamp);
            byte[] kRegion = HmacSHA256(kDate, regionName);
            byte[] kService = HmacSHA256(kRegion, serviceName);
            byte[] kSigning = HmacSHA256(kService, "aws4_request");
            return kSigning;
        }

        private static string ToHexString(byte[] array)
        {
            var hex = new StringBuilder(array.Length * 2);
            foreach (byte b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        public async Task<HttpRequestMessage> Sign(HttpRequestMessage request, string service, string region)
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

            var t = DateTimeOffset.UtcNow;
            var amzdate = t.ToString("yyyyMMddTHHmmssZ");
            request.Headers.Add("x-amz-date", amzdate);
            var datestamp = t.ToString("yyyyMMdd");

            var canonical_request = new StringBuilder();
            canonical_request.Append(request.Method + "\n");
            canonical_request.Append(request.RequestUri.AbsolutePath + "\n");

            var canonicalQueryParams = GetCanonicalQueryParams(request);

            canonical_request.Append(canonicalQueryParams + "\n");

            var signedHeadersList = new List<string>();

            foreach (var header in request.Headers.OrderBy(a => a.Key.ToLowerInvariant()))
            {
                canonical_request.Append(header.Key.ToLowerInvariant());
                canonical_request.Append(":");
                canonical_request.Append(string.Join(",", header.Value.Select(s => s.Trim())));
                canonical_request.Append("\n");
                signedHeadersList.Add(header.Key.ToLowerInvariant());
            }

            canonical_request.Append("\n");

            var signed_headers = string.Join(";", signedHeadersList);

            canonical_request.Append(signed_headers + "\n");

            var content = "";
            if (request.Content != null)
            {
                content = await request.Content.ReadAsStringAsync();
            }
            var payload_hash = Hash(content);

            canonical_request.Append(payload_hash);

            var credential_scope = $"{datestamp}/{region}/{service}/aws4_request";

            var string_to_sign = $"{algorithm}\n{amzdate}\n{credential_scope}\n" + Hash(canonical_request.ToString());

            var signing_key = GetSignatureKey(_secret_key, datestamp, region, service);
            var signature = ToHexString(HmacSHA256(signing_key, string_to_sign));

            request.Headers.TryAddWithoutValidation("Authorization", $"{algorithm} Credential={_access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}");

            if (!string.IsNullOrEmpty(_token))
            {
                request.Headers.TryAddWithoutValidation("x-amz-security-token", _token);
            }

            return request;
        }

        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            var keys = querystring.AllKeys.OrderBy(a => a).ToArray();
            var queryParams = keys.Select(key => $"{key}={querystring[key]}");
            var canonicalQueryParams = string.Join("&", queryParams);
            return canonicalQueryParams;
        }
    }
}

// /Services/GoogleAuthService.cs
using OtpNet;

namespace WebBackend.Services
{
    public class GoogleAuthService
    {
        public bool VerifyCode(string secretKey, string code)
        {
            var totp = new Totp(Base32Encoding.ToBytes(secretKey));
            return totp.VerifyTotp(code, out _);
        }
    }
}

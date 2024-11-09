// /Services/JwtService.cs
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace WebBackend.Services
{

    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly string _jwtKey;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;
        private readonly double _jwtExpiryMinutes;

        public JwtService(IConfiguration config)
        {
            _config = config;
            _jwtKey = _config["JWT:Key"] ?? throw new ArgumentNullException("JWT:Key is missing in configuration.");
            _jwtIssuer = _config["JWT:Issuer"] ?? throw new ArgumentNullException("JWT:Issuer is missing in configuration.");
            _jwtAudience = _config["JWT:Audience"] ?? throw new ArgumentNullException("JWT:Audience is missing in configuration.");
            _jwtExpiryMinutes = double.TryParse(_config["JWT:ExpiryMinutes"], out var expiry) ? expiry : throw new ArgumentException("JWT:ExpiryMinutes is missing or invalid in configuration.");
        }

        public string GenerateToken(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username is required to generate a token.");

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtIssuer,
                audience: _jwtAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_jwtExpiryMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
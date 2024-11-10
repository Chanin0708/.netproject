using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebBackend.Models;
using WebBackend.Services;
using WebBackend.DTOs;
using WebBackend.Data;
using MongoDB.Driver;
using System;
using WebBackend.Helpers;

namespace WebBackend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly WebBackendMongoDbContext _context;
        private readonly UserService _userService;
        private readonly JwtService _jwtService;
        private readonly OtpService _otpService;
        private readonly GoogleAuthService _googleAuthService;
        private readonly EmailService _emailService;
        private readonly TimeZoneInfo _bangkokTimeZone;

        public AuthController(WebBackendMongoDbContext context, UserService userService, JwtService jwtService, OtpService otpService, GoogleAuthService googleAuthService, EmailService emailService)
        {
            _context = context;
            _userService = userService;
            _jwtService = jwtService;
            _otpService = otpService;
            _googleAuthService = googleAuthService;
            _emailService = emailService;
            _bangkokTimeZone = TimeZoneInfo.FindSystemTimeZoneById("SE Asia Standard Time");
        }

        private DateTime GetBangkokTime() => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _bangkokTimeZone);

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDTO request)
        {
            if (await _context.Users.Find(u => u.Username == request.Username || u.Email == request.Email).AnyAsync())
                return BadRequest("User or email already exists");

            if (string.IsNullOrEmpty(request.Password))
                return BadRequest("Password cannot be null or empty");

            var hashedPassword = _userService.HashPassword(request.Password);
            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PasswordHash = hashedPassword,
                TwoFactorAuthentype = "",
                CreateDateTime = DateTime.Now.AddHours(7),
                LastUpdate = DateTime.Now.AddHours(7)
            };

            await _context.Users.InsertOneAsync(user);

            if (user.UserId != null && request.Password != null)
            {
                await _userService.SaveEncryptedPasswordAsync(user.UserId, hashedPassword);
            }

            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDTO request)
        {
            if (string.IsNullOrEmpty(request.Password))
                return BadRequest(new { Message = "Password cannot be null or empty" });

            var user = await _context.Users.Find(u => u.Username == request.Username).FirstOrDefaultAsync();

            if (user != null && user.StatusAccount == "locked")
                return Unauthorized(new { Message = "Account is locked. Please check your email for further instructions." });

            if (user == null || string.IsNullOrEmpty(user.PasswordHash) || !_userService.VerifyPassword(request.Password, user.PasswordHash))
            {
                if (user != null)
                {
                    user.CountLogin += 1;
                    user.LastUpdate = GetBangkokTime();

                    if (user.CountLogin >= 5)
                    {
                        user.StatusAccount = "locked";
                        await _context.Users.ReplaceOneAsync(u => u.UserId == user.UserId, user);
                        return Unauthorized(new { Message = "Account is locked. Please check your email for further instructions." });
                    }

                    await _context.Users.ReplaceOneAsync(u => u.UserId == user.UserId, user);
                }

                return Unauthorized(new { Message = "Invalid username or password" });
            }

            if (user.TwoFactorAuthen)
            {
                if (user.TwoFactorAuthentype == "email")
                {
                    if (string.IsNullOrEmpty(user.Email))
                        return BadRequest(new { Message = "User email is missing." });

                    // Delete any existing OTP records for this user
                    await _context.OtpCodes.DeleteManyAsync(o => o.UserId == user.UserId);

                    // Generate and send a new OTP
                    var otp = _otpService.GenerateOtp();
                    var referenceNumber = _otpService.GenerateReferenceNo();

                    // string subject = "Your OTP Code";
                    string toEmail = user.Email;
                    string messageBody = $"Your OTP code is: {otp}";
                    // await _emailService.SendEmailAsync(user.Email, subject, messageBody);

                    // await _otpService.SendOtp(user.Email, otp);
                    await _emailService.SendOtpEmailAsync(user.Email, user.FirstName ?? "User", user.LastName ?? "User", otp, referenceNumber);

                    // Insert the new OTP with a 15-minute expiration in Bangkok time
                    var otpCode = new OtpCode
                    {
                        UserId = user.UserId,
                        ReferenceNo = referenceNumber,
                        Code = otp,
                        Expiry = DateTime.Now.AddHours(7).AddMinutes(15)
                    };
                    await _context.OtpCodes.InsertOneAsync(otpCode);

                    user.LastUpdate = DateTime.Now.AddHours(7);
                    await _context.Users.ReplaceOneAsync(u => u.UserId == user.UserId, user);

                    return Ok(new { Message = "OTP sent to email. Please verify using the OTP." });
                }
                else if (user.TwoFactorAuthentype == "google authen")
                {
                    return Ok(new { Message = "Please enter your Google Authenticator code." });
                }
            }

            user.CountLogin = 0;
            user.StatusAccount = "active";
            user.LastUpdate = DateTime.Now.AddHours(7);
            await _context.Users.ReplaceOneAsync(u => u.UserId == user.UserId, user);

            if (string.IsNullOrEmpty(user.Username))
                return BadRequest(new { Message = "User username is missing." });

            var token = _jwtService.GenerateToken(user.Username);
            return Ok(new { Message = "Login successful", Token = token });
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpVerificationRequest request)
        {
            if (string.IsNullOrEmpty(request.Username))
                return BadRequest(new { Message = "Username is required." });

            var user = await _context.Users.Find(u => u.Username == request.Username).FirstOrDefaultAsync();
            if (user == null)
                return Unauthorized(new { Message = "Invalid user" });

            if (user.TwoFactorAuthentype == "email")
            {
                if (string.IsNullOrEmpty(request.OtpCode))
                    return BadRequest(new { Message = "OTP code is required." });

                var otpRecord = await _context.OtpCodes.Find(o => o.UserId == user.UserId && o.Code == request.OtpCode).FirstOrDefaultAsync();
                if (otpRecord == null || otpRecord.Expiry < GetBangkokTime())
                    return Unauthorized(new { Message = "Invalid or expired OTP" });

                await _context.OtpCodes.DeleteOneAsync(o => o.UserId == user.UserId);

                if (string.IsNullOrEmpty(user.Username))
                    return BadRequest(new { Message = "User's username is missing." });

                var token = _jwtService.GenerateToken(user.Username);
                return Ok(new { Message = "Login successful", Token = token });
            }
            else if (user.TwoFactorAuthentype == "google authen")
            {
                if (string.IsNullOrEmpty(user.SecretKey))
                    return BadRequest(new { Message = "User's Google Authenticator secret key is missing." });

                if (string.IsNullOrEmpty(request.OtpCode))
                    return BadRequest(new { Message = "Google Authenticator code is required." });

                bool isGoogleOtpValid = _googleAuthService.VerifyCode(user.SecretKey, request.OtpCode);
                if (!isGoogleOtpValid)
                    return Unauthorized(new { Message = "Invalid Google Authenticator code" });

                if (string.IsNullOrEmpty(user.Username))
                    return BadRequest(new { Message = "User's username is missing." });

                var token = _jwtService.GenerateToken(user.Username);
                return Ok(new { Message = "Google Authenticator code verified successfully", Token = token });
            }

            return BadRequest(new { Message = "Invalid 2FA method" });
        }
    }
}

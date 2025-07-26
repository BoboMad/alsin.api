using Alsin.Api.Models;
using Alsin.Api.Models.Enums;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Alsin.Api.Controllers.Auth.DTOs;
using Alsin.Api.JWT;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Alsin.Api.Services;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using Alsin.Api.Data;
using Microsoft.AspNetCore.RateLimiting;
using Azure.Core;
using Alsin.Api.Helpers;

namespace Alsin.Api.Controllers.Auth
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JwtTokenGenerator _jwtTokenGenerator;
        private readonly EmailService _emailService;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly ApplicationDbContext _context;
        public AuthController(UserManager<ApplicationUser> userManager, JwtTokenGenerator jwtTokenGenerator, EmailService emailService, SignInManager<ApplicationUser> signInManager, IConfiguration config, ApplicationDbContext context)
        {
            _userManager = userManager;
            _jwtTokenGenerator = jwtTokenGenerator;
            _emailService = emailService;
            _signInManager = signInManager;
            _config = config;
            _context = context;
        }

        [EnableRateLimiting("fixed")]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto model)
        {
            try
            {
                if(!ModelState.IsValid) {
                    return this.BadRequestMessage("Invalid user information");
                }

                var userExists = await _userManager.FindByEmailAsync(model.Email);
                if (userExists != null)
                {
                    if (userExists.EmailConfirmed)
                    {
                        return this.ConflictMessage("User already exists!"); 
                    }

                    await _userManager.DeleteAsync(userExists);
                }

                var user = new ApplicationUser
                {
                    Email = model.Email,
                    UserName = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    DateOfBirth = model.DateOfBirth,
                    EmailConfirmed = false,
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (!result.Succeeded)
                    return this.BadRequestMessage("Account registration failed, please try again.");

                await _userManager.AddToRoleAsync(user, UserRoles.User.ToString());
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var html = await _emailService.RenderEmailTemplateAsync("render-confirmation-email", new Dictionary<string, string>
                {
                    { "name", user.FirstName },
                    { "email", user.Email },
                    { "token", token }
                });
                await _emailService.SendConfirmationEmail(user.Email, html);

                return this.OkMessage("User created successfully. Please check your email to confirm your account.");
            }
            catch (Exception ex)
            {
                return this.BadRequestMessage("An error occurred during registration");
            }
        }

        [EnableRateLimiting("confirm-email")]
        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return this.BadRequestMessage("Invalid email.");

            if (user.EmailConfirmed)
                return this.BadRequestMessage("Email already confirmed, please log in");

            var result = await _userManager.ConfirmEmailAsync(user, request.Token);
            if (!result.Succeeded)
                return this.BadRequestMessage("Email confirmation failed, try requesting a new confirmation link.");

            await _userManager.UpdateSecurityStampAsync(user);

            return this.OkMessage("Email confirmed successfully!");
        }

        [EnableRateLimiting("fixed")]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
            {
                return this.UnauthorizedMessage("Invalid credentials.");
            }

            var result = await _signInManager.PasswordSignInAsync(
                user,
                loginDto.Password,
                isPersistent: false,
                lockoutOnFailure: true
            );

            if (result.Succeeded)
            {
                await RevokeTokenChain(user.Id);

                var roles = await _userManager.GetRolesAsync(user);
                var token = _jwtTokenGenerator.GenerateToken(user, roles);

                var refreshTokenValue = GenerateSecureToken();

                var refreshTokenExpirationDays = _config.GetValue<int>("JwtSettings:RefreshTokenExpirationDays");
                var refreshToken = new RefreshToken
                {
                    TokenHash = HashToken(refreshTokenValue),
                    UserId = user.Id,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(refreshTokenExpirationDays)
                };

                _context.RefreshTokens.Add(refreshToken);
                await _context.SaveChangesAsync();

                var AccessTokenExpirationMinutes = _config.GetValue<int>("JwtSettings:AccessTokenExpirationMinutes");

                Response.Cookies.Append("jwt_token", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddMinutes(AccessTokenExpirationMinutes)
                });

                Response.Cookies.Append("refresh_token", refreshTokenValue, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddDays(refreshTokenExpirationDays)
                }); 

                return this.OkMessage("Logged in successfully");
            }

            if (result.IsNotAllowed)
            {
                return this.UnauthorizedMessage("Login not allowed. Please confirm your email.");
            }

            if (result.IsLockedOut)
            {
                return this.ForbiddenMessage("Account locked due to too many failed attempts.");
            }

            return this.UnauthorizedMessage("Invalid login attempt.");
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("jwt_token");
            return this.OkMessage("Logged out");
        }

        [EnableRateLimiting("fixed")]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshTokenValue))
                return this.UnauthorizedMessage("Refresh token is missing.");

            var refreshTokenHash = HashToken(refreshTokenValue);

            var refreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.TokenHash == refreshTokenHash);

            if (refreshToken == null)
                return this.UnauthorizedMessage ("refresh_token_invalid");

            if (refreshToken.IsRevoked || refreshToken.ExpiresAt <= DateTime.UtcNow)
            {
                // Check for reuse attack
                if (refreshToken.ReplacedByTokenHash != null)
                {
                    await RevokeTokenChain(refreshToken.UserId);
                    return this.UnauthorizedMessage("refresh_token_reused");
                }

                return this.UnauthorizedMessage("refresh_token_expired_or_revoked");
            }

            if (refreshToken.CreatedAt < DateTime.UtcNow.AddDays(-30))
            {
                await RevokeTokenChain(refreshToken.UserId);
                return this.UnauthorizedMessage("session_expired");
            }

            var user = refreshToken.User;
            var roles = await _userManager.GetRolesAsync(user);

            var newAccessToken = _jwtTokenGenerator.GenerateToken(user, roles);
            var newRefreshTokenValue = GenerateSecureToken();
            var newRefreshToken = new RefreshToken
            {
                TokenHash = HashToken(newRefreshTokenValue),
                UserId = user.Id,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };

            refreshToken.IsRevoked = true;
            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.ReplacedByTokenHash = newRefreshToken.TokenHash;

            _context.RefreshTokens.Add(newRefreshToken);
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            // Update cookies
            Response.Cookies.Append("jwt_token", newAccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });

            Response.Cookies.Append("refresh_token", newRefreshTokenValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = newRefreshToken.ExpiresAt
            });

            return this.OkMessage("Token refreshed");
        }

        [EnableRateLimiting("fixed")]
        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmation(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null || user.EmailConfirmed)
                    return Ok(); 

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var html = await _emailService.RenderEmailTemplateAsync("render-confirmation-email", new Dictionary<string, string>
                                {
                                    { "name", user.FirstName },
                                    { "token", token }
                                });
                await _emailService.SendConfirmationEmail(user.Email!, html);

                return this.OkMessage("Confirmation link resent, check your mail.");
            }
            catch (Exception ex)
            {
                return this.BadRequestMessage(ex.Message);
            }
        }

        private async Task RevokeTokenChain(string userId)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }
            await _context.SaveChangesAsync();
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                user.Email,
                user.FirstName,
                user.LastName,
                Role = roles,
            });
        }

        private string GenerateSecureToken()
        {
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private string HashToken(string token)
        {
            var secret = _config["JwtSettings:RefreshTokenHashSecret"];
            using var hmac = new HMACSHA256(Convert.FromHexString(secret));
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(token)));
        }
    }
}

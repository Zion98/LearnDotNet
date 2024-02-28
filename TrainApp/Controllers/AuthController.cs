using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using TrainApp.Dtos;
using TrainAppService.Dtos;
using TrainAppService.Models;
using TrainAppService.Services;
using IEmailService = TrainAppService.Services.IEmailService;
using Login = TrainAppService.Dtos.Login;

namespace TrainApp.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        // private readonly TrainAppDbContext trainAppDbContext;
        //

        private readonly UserManager<IdentityUser> _userManager;

        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly IEmailService _emailService;


        private readonly SignInManager<IdentityUser> _signInManager;


        private readonly IUserService _userService;

        private readonly IConfiguration _configuration;

        public AuthController(

            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager,

            IUserService userService
          )
        {

            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
            _userService = userService;
        }


        [HttpPost]
        public async Task<IActionResult> Register([FromBody] User registerUser)
        {
            var tokenResponse = await _userService.CreateUserWithTokenAsync(registerUser);

            if (tokenResponse.IsSuccess)
            {

                _ = await _userService.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                //Add token to verify the email
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email });

                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);


                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"We have sent a confirmation link to your Email {registerUser.Email}" });

            }

            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = tokenResponse.Message, IsSuccess = false });


        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login login)

        {

            var loginOtpResponse = await _userService.GetOtpByLoginAsync(login);

            if (loginOtpResponse.Response != null)
            {
                //Check if user exists
                var user = loginOtpResponse.Response.User;//await _userManager.FindByNameAsync(login.Username);

                var ifPasswordCorrect = await _userManager.CheckPasswordAsync(user, login.Password);


                if (user.TwoFactorEnabled)
                {

                    var token = loginOtpResponse.Response.Token;

                    var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status201Created, new Response { Status = loginOtpResponse.IsSuccess.ToString(), Message = $"We have sent an OTP to your Email {user.Email}" });

                }
                if (user != null && ifPasswordCorrect)
                {
                    var authClaims = new List<Claim>
                {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

                    var userRoles = await _userManager.GetRolesAsync(user);

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }


                    var jwtToken = GetToken(authClaims);

                    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(jwtToken), expiration = jwtToken.ValidTo });

                }

            }
            return Unauthorized();

        }


        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {

            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);

            if (!signIn.Succeeded)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Invalid Code" });
            }

            if (user != null)
            {
                var authClaims = new List<Claim>
                {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

                var userRoles = await _userManager.GetRolesAsync(user);

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = GetToken(authClaims);

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(jwtToken), expiration = jwtToken.ValidTo });

            }
            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Invalid Code" });


        }


        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var ForgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);

                var message = new Message(new string[] { user.Email }, "Forgot Password Link", ForgotPasswordLink!);

                _emailService.SendEmail(message);


                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Password changed request is sent on Email {user.Email}. Please check your email." });

            }

            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = $"Could not send link to mail, please try again later. " });

        }


        [HttpGet("reset-password")]
        // [AllowAnonymous]
        // [Route]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new { model });
        }


        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);

            if (user != null)
            {

                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Password changed request is sent on Email {user.Email}. Please check your email." });
            }

            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = $"Could not send link to mail, please try again later. " });

        }



        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(

                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

        // [HttpGet]
        // public IActionResult TestEmail()
        // {

        //     var message = new Message(new string[] { "adeyemioluwasegun98@gmail.com" ,"castro@gmail.com"}, "Test", "<h1>Subscribe to my Channel</h1>");

        //     _emailService.SendEmail(message);

        //     return StatusCode(StatusCodes.Status200OK, new Dtos.Response { Status = "Success", Message = "Email sent successfully" });

        // }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {

            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Dtos.Response { Status = "Success", Message = "Email verified succesfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Dtos.Response { Status = "Error", Message = "This email could not be confirmed " });

        }
    }


}
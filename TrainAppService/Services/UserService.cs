using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using TrainAppService.Dtos;
using TrainAppService.Models;

namespace TrainAppService.Services
{

    public class UserService : IUserService
    {

        private readonly UserManager<IdentityUser> _userManager;

        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly SignInManager<IdentityUser> _signInManager;

        public UserService(

            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            // IEmailService emailService,
            // IConfiguration configuration,
            SignInManager<IdentityUser> signInManager
          )
        {

            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user)
        {
            var assignedRoles = new List<string>();
            foreach (var role in roles)
            {
                var roleExists = await _roleManager.RoleExistsAsync(role);
                if (roleExists)

                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRoles.Add(role);
                    }

            }

            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Roles has been assigned", Response = assignedRoles };
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(User registerUser)
        {
            //Check if user and exists in the database
            var userExist = _userManager.FindByEmailAsync(registerUser.Email);


            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exists" };
                //StatusCode(StatusCodes.Status403Forbidden, new Dtos.Response { Status = "Error", Message = "User already exists" });
            }


            //Add User in the Database;
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };

            var result = await _userManager.CreateAsync(user, registerUser.Password);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse> { Response = new CreateUserResponse() { User = user, Token = token }, IsSuccess = false, StatusCode = 201, Message = $"User created successfully, check your email- {user.Email} to confirm your account." };
                // return StatusCode(StatusCodes.Status201Created, new Dtos.Response { Status = "Success", Message = $"User created successfully, check your email- {user.Email} to confirm your account." });
            }

            return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "User failed to create." };
            // return StatusCode(StatusCodes.Status500InternalServerError, new Dtos.Response { Status = "Error", Message = "User failed to create" });s

        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(Login login)
        {
            //Check if user exists
            var user = await _userManager.FindByNameAsync(login.Username);

            if (user == null)
            {
                return new ApiResponse<LoginOtpResponse>
                {

                    IsSuccess = true,
                    StatusCode = 404,
                    Message = $"User does not exist."
                };
            }


            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, login.Password, false, false);


            if (user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = token,
                        IsTwoFactorEnabled = user.TwoFactorEnabled
                    },
                    IsSuccess = true,
                    StatusCode = 500,
                    Message = $"Otp sent to email- {user.Email}."
                };

            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = string.Empty,
                        IsTwoFactorEnabled = user.TwoFactorEnabled
                    },
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = $"2FA is not enabled."
                };
            }



        }
    }
}
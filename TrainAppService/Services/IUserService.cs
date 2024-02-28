using Microsoft.AspNetCore.Identity;
using TrainAppService.Dtos;
using TrainAppService.Models;

namespace TrainAppService.Services
{


    public interface IUserService
    {

        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(User registerUser);


        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user);



        Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(Login login);

    }
}
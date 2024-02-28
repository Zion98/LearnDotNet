using Microsoft.AspNetCore.Identity;

namespace TrainAppService.Dtos
{
    public class CreateUserResponse
    {
        public string? Token { get; set; }

        public IdentityUser? User { get; set; }
    }
}
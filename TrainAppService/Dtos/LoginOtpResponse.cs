using Microsoft.AspNetCore.Identity;

namespace TrainAppService.Dtos
{
    public class LoginOtpResponse
    {
        public string? Token { get; set; } = null;

        public bool IsTwoFactorEnabled { get; set; }

        public IdentityUser User { get; set; } = null!;
    }
}
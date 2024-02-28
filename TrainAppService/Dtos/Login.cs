using System.ComponentModel.DataAnnotations;

namespace TrainAppService.Dtos
{

    public class Login
    {
        [Required(ErrorMessage = "User name is required")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
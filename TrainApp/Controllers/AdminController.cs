using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TrainApp.Controllers
{

    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController
    {

        [HttpGet("employees")]

        public IEnumerable<string> Get()
        {
            return new List<string> { "Ahmed", "Ali", "Alhassan" };
        }

    }
}
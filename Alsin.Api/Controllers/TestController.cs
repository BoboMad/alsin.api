using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Runtime.CompilerServices;

namespace Alsin.Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        public TestController()
        {
            
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            await Task.Delay(1000); 
            var newObject = new
            {
                Message = "Hello from TestController",
                Timestamp = DateTime.UtcNow
            };
            return Ok(newObject);
        }
    }
}

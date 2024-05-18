using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWT_DotNet_Core_8.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [Authorize]
        [HttpPost]
        [Route("/isauthorized")]
        public string IsAuthorized()
        {            
            return "yes";
        }
       
        [HttpPost]
        [Route("/noauth")]
        public string NoAuth()
        {
            return "yes";
        }
    }
}

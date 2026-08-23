using Microsoft.AspNetCore.Mvc;

namespace OrderingApi;

[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    
    [HttpGet("{id}")]
    public IActionResult Get([FromRoute]int id)
    {
        var users = GetUsers();

        if (id < 0 || id > users.Length)
            return NotFound(new { Error = "User not found" });

        return Ok(users[id]);
    }
    
    [HttpGet("Admin/{role}")]
    public IActionResult Get([FromRoute]string role)
    {
        if(role.ToLower() == "itguy")
            return Ok("<REDACTED>");

        return Unauthorized("Only members of IT has access to this dashboard");
    }
}

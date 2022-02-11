using AuthTest.Data;
using AuthTest.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AccountController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(UserLogin model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.Email);
                if (user != null && !user.EmailConfirmed)
                {
                    ModelState.AddModelError("message", "Email not confirmed yet");
                    return BadRequest(model);
                }
                if (await userManager.CheckPasswordAsync(user, model.Password) == false)
                {
                    ModelState.AddModelError("message", "Invalid credentials");
                    return BadRequest(model);
                }

                var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, false, true);
                if (result.Succeeded)
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        // new Claim(ClaimTypes.Role, SeedData.AppRole.Admin.ToString()),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };

                    var userRoles = await userManager.GetRolesAsync(user);
                    if (userRoles != null)
                    {
                        foreach (var userRole in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                        }
                    }
                                        
                    // await userManager.AddClaimAsync(user, new Claim("UserRole", "Admin"));
                    var token = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo
                    });
                }
                else if (result.IsLockedOut)
                {
                    ModelState.AddModelError("message", "Account locked");
                }
                else
                {
                    ModelState.AddModelError("message", "Invalid login attempt");
                }
            }
            return Unauthorized(ModelState);
        }

        [HttpPost("register"), AllowAnonymous]
        public async Task<IActionResult> Register(UserRegistration request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
                
            var userCheck = await userManager.FindByEmailAsync(request.Email);
            if (userCheck == null)
            {
                var user = new ApplicationUser
                {
                    UserName = request.Email,
                    NormalizedUserName = request.Email,
                    Email = request.Email,
                    PhoneNumber = request.PhoneNumber,
                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true,
                };
                var result = await userManager.CreateAsync(user, request.Password);

                // Assign to Admin role - this is just an example of managing the role.
                await userManager.AddToRoleAsync(user, SeedData.AppRole.Admin.ToString());

                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    if (result.Errors.Count() > 0)
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("message", error.Description);
                        }
                    }
                    return BadRequest(request);
                }
            }
            else
            {
                ModelState.AddModelError("message", "Email already exists.");
                return BadRequest(request);
            }            
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            //var certKey = new X509SecurityKey(new X509Certificate2(""));
            var token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            return token;
        }
    }
}

using Microsoft.AspNetCore.Identity;

namespace AuthTest.Data
{
    public static class SeedData
    {
        public enum AppRole { 
            Admin = 0,
            Teacher = 1,
            Student = 2
        };


        public static async Task InitialiseRoles(RoleManager<IdentityRole> roleManager)
        {
            foreach(var roleName in Enum.GetNames(typeof(AppRole))) 
                await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

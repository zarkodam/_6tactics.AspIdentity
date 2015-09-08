using Microsoft.AspNet.Identity.EntityFramework;
using _6tactics.AspIdentity.Models;

namespace _6tactics.AspIdentity.DataAccess
{
    public class IdentityDbContext : IdentityDbContext<ApplicationUser>
    {
        public IdentityDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
        }


        public static IdentityDbContext Create()
        {
            return new IdentityDbContext();
        }
    }
}
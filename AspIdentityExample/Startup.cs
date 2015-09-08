using _6tactics.AspIdentity.Initialization;
using AspIdentityExample;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(Startup))]

namespace AspIdentityExample
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            IdentityConfig.ConfigureAuth(app);
        }
    }
}

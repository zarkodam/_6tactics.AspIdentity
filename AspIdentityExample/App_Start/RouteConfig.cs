using System.Web.Mvc;
using System.Web.Routing;

namespace AspIdentityExample
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.LowercaseUrls = true;

            routes.MapRoute(
                name: "ResetPassword",
                url: "Account/ResetPassword/{code}",
                defaults: new { controller = "Account", action = "Index", code = UrlParameter.Optional }
            );

            routes.MapRoute(
                name: "CompleteRegistration",
                url: "Account/CompleteRegistration/{code}",
                defaults: new { controller = "Account", action = "Index", code = UrlParameter.Optional }
            );

            routes.MapRoute(
                name: "ManageIndex",
                url: "Manage/Index/{message}",
                defaults: new { controller = "Manage", action = "Index", message = UrlParameter.Optional }
            );

            routes.MapRoute(
               name: "AccountLogin",
               url: "Account/Login/{returnUrl}/{message}",
               defaults: new { controller = "Account", action = "Login", returnUrl = UrlParameter.Optional, message = UrlParameter.Optional }
           );

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );
        }
    }
}

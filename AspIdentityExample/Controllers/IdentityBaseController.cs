using _6tactics.AspIdentity.Models;
using _6tactics.AspIdentity.Repositories;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AspIdentityExample.Controllers
{
    public class IdentityBaseController : Controller
    {
        #region Fields

        protected readonly IIdentityRepository IdentityRepository;

        #endregion

        #region Constructors

        public IdentityBaseController(IIdentityRepository identityRepository)
        {
            IdentityRepository = identityRepository;
        }

        #endregion

        #region AccountHelpers

        public enum AccountMessageId
        {
            ResetPasswordSuccess,
            ConfirmationEmailSended,
            UserOrEmailConfirmationError,
            ConfirmationSuccessed,
            RegistrationCompleted,
            Error
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };

                if (UserId != null) properties.Dictionary[XsrfKey] = UserId;

                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }

        #endregion

        #region ManageHelpers

        protected async Task<bool> HasPassword()
        {
            ApplicationUser user = await IdentityRepository.UserManager.FindByIdAsync(User.Identity.GetUserId());

            return user?.PasswordHash != null;
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error,
            ChangeEmailSuccess
        }

        #endregion

        #region UserAdminstrationHelpers

        protected void IsResultNotSucceededAddModelError(IdentityResult result)
        {
            if (!result.Succeeded) ModelState.AddModelError("", result.Errors.First());
        }

        #endregion

        #region RolesAdministrationHelpers

        #endregion

        #region CommonHelpers

        protected const string XsrfKey = "XsrfId";

        protected void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError("", error);
        }

        protected IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;


        #endregion

        #region Dispose

        protected override void Dispose(bool disposing)
        {
            IdentityRepository.Dispose(IdentityRepository, disposing);
            base.Dispose(disposing);
        }

        #endregion
    }
}
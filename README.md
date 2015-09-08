# _6tactics.AspIdentity
_6tactics.AspIdentity separates, configures and extends asp.net identity 2 functionality in another project that can be used in any asp.net app.

*note: for localized display name attributes I strongly recommend to move view models in web(main) project.*

## Added new functionalities: ##

### Managing users includes (UserAdministrationController): ######
 - create
   - create and activate account with user name, email, password and adding user to groups
   - create and activate account  with user name, email as well as adding user to groups, but user gets email to create his password
 - edit
   - change user name, email, roles membership and password reset - user gets email to change his password(optional)
 - delete
   - delete user account
 - only administrator can make changes

### Maniging roles includes (RolesAdministrationController): ######
 - create
   - create role
 - edit
   - edit role name
 - delete
   - delete role


*note: users with administrator role can make changes*


## Changed / extended functionalities: ##

### Login view (AccountController): ######
 - starts with username not email
 - "Forgot your password?" sends email to user with confirmation link for changing password 

### Register view (AccountController): ######
 - after registration user gets email to confirm his registration

### Index view (ManageController): ######
 - added email update so that user can change his current email


## Also check in AspIdentityExample(main web project): ##
 - Startup.cs
 - email setting example in web.config 
 - App_Readme/migrationReadme.txt
 - App_Start/RouteConfig.cs
 - App_Start/UnityConfig.cs

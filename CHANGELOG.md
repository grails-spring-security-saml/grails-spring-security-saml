## Changelog

### Installation

## 6.0.11 - 08.04.25
### Changed
* Rewrote DefaultRegistrationResolver to use defaultIdp as fallback to the registrationId that is associated with the current login attempt
* defaultIdp is no longer necessary to activate the filters at the assertionConsumerService and singleLogoutService URL paths (only the latter matter and all IDPs in the provider list are supported, assuming they log in/out at this endpoint) 

## 6.0.10 - 03.04.25
### Changed
* Added nameIdFormat as a configuration setting to work around missing NameIDFormat functionality in spring-security-saml2-service-provider
* The above change is only a temporary workaround and should not be relied on to work in future versions.
* The library should read the supported NameIDFormats from the IDP metadata in the first place

## 6.0.9 - 28.02.25
### Changed
* Added loginNonceExpiry as a configuration setting and increased the expiry time to 30 minutes

## 6.0.8 - 30.01.25
### Changed
* Upgraded the build system of the plugin to grails 6

## 6.0.7 - 09.12.24
### Changed
* Implemented LoginNonce and LogoutNonce to support SameSite=Lax for JSESSONID (but SameSite=None for LoginNonce/LogoutNonce)

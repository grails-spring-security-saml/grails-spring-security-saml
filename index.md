{% include_relative README.md %}

### Changes in the Grails 6 version of the plugin

The so called `spring-security-saml2-service-provider` has a glaring flaw.
As of 2022, cookies are set to be `SameSite=Strict` or `SameStrict=Lax` by default, depending on your browser.
Since SAML is a single sign on protocol, it is inherently cross site by design.
The identity provider (IDP) and service provider (SP) do not have to be on the same origin.
While this does not fundamentally break the plugin as it is still possible to initiate an SSO Login, 
the spring service provider is unable to correlate the returning redirect to the originating session,
which means that if you open a protected URL directly, e.g. through a bookmark, you be redirected into a newly created
session on the index page. The quick and dirty solution is to set the JSESSIONID Cookie to `SameSite=None`,
undoing the SameSite protection, however, this will undo the CSRF protection that SameSite cookies grant.

What do the developers in charge of Spring Security have to say? Well, let's say they don't want to make it easy.

```
I'm not certain how to address this without creating another cookie, making me think that I might as well use the session cookie after all.
```
https://github.com/spring-projects/spring-security/issues/14013#issuecomment-1854823760

Well, he started on the right track but arrived at exactly the wrong answer! We want the JSESSIONID token to be as secure as possible,
hence `SameSite=Strict` or `SameStrict=Lax`. So what we want is another cookie or two, that are limited in scope
so that they can only be used in the context of an SSO login and logout request.

#### Enter the login nonce...

```yaml
grails:
   plugins:
      springsecurity:
          saml:
            loginNonce: true
```

What does this do? Before being sent off to the IDP, the SP will first generate a nonce and store it in the LoginNonce cookie and relayState and http session.
Since this LoginNonce cookie is `SameSite=None`, it will be sent back along with the relay state.
The two are checked to be identical before being used to retrieve the originating authentication request.

```yaml
grails:
   plugins:
      springsecurity:
          saml:
            logoutNonce: true
```

The LogoutNonce cookie is similar to the LoginNonce cookie, but with one caveat. Since single logout can be triggered from other service providers,
there is no opportunity to set up the LogoutNonce cookie for a given logout attempt. Instead, it is set upon successful login,
so that the SP is ready to accept a logout from the IDP at any time.
On one hand this does mean that a CSRF to the logout button is possible, but on the other hand, this is the very essence of SSO logout.
Any random service provider you have visited (including links to their logout buttons) can always log you out of your global session!
This is true with or without the LogoutNonce!

### Changes in the Grails 5 version of the plugin

The Spring Security Saml Plugin has been replaced by direct support for SAML in Spring Security Core. Some of the features of the old plugin have not been implemented and therefore have been removed in the latest version of this grails plugin.

The following configuration properties have been removed entirely.

```yaml
grails:
   plugins:
      springsecurity:
          saml:
            responseSkew:
            metadata:
                sp:
                    defaults:
                        alias:
                        local:
                        securityProfile:
                        encryptionKey:
                        tlsKey:
                        requireArtifactResolveSigned:
                        requireLogoutRequestSigned:
                        requireLogoutResponseSigned:
```

Spring Security Core now has the concept of a RelyingPartyRegistrationReposity. A RelyingPartyRegistration must be created for each Service Provider and Identity Provider pair and each pair is uniquely identified by a registrationId which is identical to the registrationId specified in the providers property. This plugin automatically generates RelyingPartyRegistrations for each IDP based on the provided XML IDP Metadata.

The entityID of the Service Provider is generated based on the pattern specified in `grails.plugins.springsecurity.saml.saml.metadata.sp.defaults.entityID` which is `{baseUrl}/saml2/service-provider-metadata/{registrationId}` by default.

The location specified in the AssertionConsumerService tag is now `{baseUrl}/login/saml2/sso/{registrationId}`.
The location specified in the SingleLogoutService tag is now `{baseUrl}/logout/saml2/sso/{registrationId}`.

Finally, the Service Provider needs to include the certificate specified by `grails.plugins.springsecurity.saml.saml.metadata.sp.defaults.signingKey`

The generated metadata files are available under `/saml2/service-provider-metadata/{registrationId}`.

Specifying both `assertionConsumerService` and `defaultIdp` will create a custom Filter at the Path `assertionConsumerService` which can only login to the IDP specified in `defaultIdp` (restriction lifted since 6.0.11). This is intended to allow an existing application to upgrade to the latest version of this plugin without having to re-register its metadata if all it does is integrate a single service provider with a single identity provider.

```yaml
grails:
   plugins:
      springsecurity:
          saml:
            metadata:
                defaults:
                    entityID: {baseUrl}
                    assertionConsumerService: {baseUrl}/saml/SSO
                    singleLogoutService: {baseUrl}/saml/SingleLogout
```

### Configuration
The Plugin basically creates a bridge from your application configuration to both the Spring Security SAML Plugin and the Grails Spring Security Plugin. Instead of having to map all of the beans in your application, the plugin wires the SAML Plugin beans from your application configuration.

All configuration items are preceeded with grails >> plugin >> springsecurity >> saml.  The following is a list of all of the configuration options available.

#### Spring Security Starter
The spring security starter may need to be added to your build.gradle

```
compile "org.springframework.boot:spring-boot-starter-security"
```

#### Prevent SecurityFilterAutoConfiguration

The security auto configuration of spring boot is disabled by default.
However this plugin has a dependency on spring-security-config which may automatically
activate the configuration. It must be disabled to prevent it from interfering
the grails framework which installs its own filters.

```
package app

import grails.boot.GrailsApp
import grails.boot.config.GrailsAutoConfiguration
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration

@EnableAutoConfiguration(exclude = [SecurityFilterAutoConfiguration])
class Application extends GrailsAutoConfiguration {
    static void main(String[] args) {
        GrailsApp.run(Application, args)
    }
}
```

#### Spring Security Classes
The plugin requires that the Spring Security Classes that are created with the s2-quickstart, are present in your application.
To run s2-quickstart, see [s2-quickstart](https://grails-plugins.github.io/grails-spring-security-core/v3/#s2-quickstart)

Command Line Example

```
$> grails s2-quickstart com.jeffwils UserAcct Role
```

This will create the Spring Security Domain Classes and it will create/modify the application.groovy file. You can convert the generated configuration to yaml format and use it in application.yml as well.

Warning: Some table or column names may conflict with existing SQL keywords such as 'USER' or 'PASSWORD' on postgres or other RDBMS. If necessary these can be adjusted in the mapping block of your user domain class:

```
static mapping = {
    table 'users'
    password column: '`password`'
}
```

#### Authentication Provider
The plugin sets up a SAML Authentication provider **samlAuthenticationProvider** which can be referenced in the Grails Spring Security Plugin configuration

```yaml
grails:
   plugins:
      springsecurity:
         providerNames: ['samlAuthenticationProvider', ......]
```

#### Property Table

All of these properties can be put in either `application.yml` or `application.groovy` and they are all prefixed with:
**grails.plugins.springsecurity.saml**


| Property                          | Syntax                                             | Example Value                                                                       | Description                                                                                                                                                                                                                      |
|-----------------------------------|----------------------------------------------------|-------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| active                            | boolean                                            | true                                                                                | States whether or not SAML is active                                                                                                                                                                                             |
| afterLoginUrl                     | url string                                         | '/'                                                                                 | Redirection Url in your application upon successful login from the IDP                                                                                                                                                           |
| afterLogoutUrl                    | url string                                         | '/'                                                                                 | Redirection Url in your application upon successful logout from the IDP                                                                                                                                                          |
| loginNonce                        | boolean                                            | true                                                                                | Activates login nonce based session correlation to allow JSESSIONID to be set to SameSite=Strict. A nonce will be sent via cookie and relayState to retrieve the initiating session.                                             |
| logoutNonce                       | boolean                                            | true                                                                                | Activates logout nonce based session correlation to allow JSESSIONID to be set to SameSite=Strict. The nonce will be set upon successful authentication.                                                                         |
| userAttributeMappings             | Map                                                | [username:'funkyUserNameFromIDP']                                                   | Allows Custom Mapping if both Application and IDP Attribute Names cannot be changed.                                                                                                                                             |
| userGroupAttribute                | String Value                                       | 'memberOf'                                                                          | Corresponds to the Role Designator in the SAML Assertion from the IDP                                                                                                                                                            |
| userGroupToRoleMapping            | Map [Spring Security Role: Saml Assertion Role]    | [ROLE_MY_APP_ROLE: 'CN=MYSAMLGROUP, OU=MyAppGroups, DC=myldap, DC=example, DC=com'] | This maps the Spring Security Roles in your application to the roles from the SAML Assertion.  Only roles in this Map will be resolved.                                                                                          |
| useLocalRoles                     | boolean                                            | true                                                                                | Determine a user's role based on the existing values in the local Spring Security tables. Will merge with additional roles loaded via `userGroupAttribute` and `userGroupToRoleMapping`. Defaults to `false`.                    
| autoCreate.active                 | boolean                                            | false                                                                               | If you want the plugin to generate users in the DB as they are authenticated via SAML                                                                                                                                            
| autoCreate.key                    | domain class unique identifier                     | 'id'                                                                                | if autoCreate active is true then this is the unique id field of the db table                                                                                                                                                    |
| autoCreate.assignAuthorities      | boolean                                            | false                                                                               | If you want the plugin to insert the authorities that come from the SAML message into the UserRole Table.                                                                                                                        |
| metadata.providers                | Map [registrationId: idp file reference]           | [ping:"/pathtoIdpFile/myIdp.xml"]                                                   | Map of idp providers. Contain a registration id and reference to the idp xml file                                                                                                                                                |
| metadata.defaultIdp               | String                                             | 'https://idp.example.org/idp/shibboleth'                                            | the entityId of the default Idp from the ones listed in the metadata.provider map. If no entityId is given an IDP will be picked from the list automatically.                                                                    |
| metadata.url                      | relative url                                       | '/saml/metadata/{registrationId}'                                                   | url used to retrieve the SP metadata for your app to send to the IDP                                                                                                                                                             |
| metadata.sp.defaults.entityId     | String Value                                       | 'http://myapp.example.com'                                                          | Identifier for the Service Provider                                                                                                                                                                                              |
| metadata.sp.defaults.signingKey   | keystore alias                                     | 'mykey'                                                                             | For local entities alias of private key used to create signatures. The default private key is used when no value is provided. For remote identity providers defines an additional public key used to verify signatures.          |
| metadata.sp.defaults.nameIdFormat | String Value                                       | 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'                               |`urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`, `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` |
| keyManager.storeFile              | file reference string                              | 'classpath:security/sso-keyStore.jks'                                               |                                                                                                                                                                                                                                  |
| keyManager.storePass              | password string                                    | 'changeit'                                                                          | Keypass to keystore referenced in storeFile                                                                                                                                                                                      |
| keyManager.privateKeyFile         | file reference string                              | 'file:/etc/sso-server-key.pem'                                                      | Private key file in .pem format (encryption not supported)                                                                                                                                                                       |
| keyManager.certificateFile        | file reference string                              | 'file:/etc/sso-cert.pem'                                                            | Public certificate file in .pem format (encryption not supported)                                                                                                                                                                |
| keyManager.passwords              | password map [private key registrationId:password] | [mykey:'changeit']                                                                  | Map of registration ids and passwords if private key in storeFile is password protected                                                                                                                                          |

Notice: `metadata.sp.defaults.nameIdFormat` exists as a workaround to Spring Security's `saml2-service-provider` not reading the NameIDFormat from the xml metadata of the IDP. Expect nameIdFormat to be ignored in future versions.  

#### Example Configuration

The following is an example configuration that will allow the application to start up correctly out of the box and have all the required beans mapped. There is one build.gradle file (5.1.8 which should work with Grails 5.0.0+). The example configurations (application.groovy & application.yml) utilize some of the defaults in the plugin and will need to be changed in your application (The SP and IDP specific) settings so that it will work with your service provider/identity provider configuration.

build.gradle 5.1.8

```
buildscript {
    repositories {
        maven { url "https://repo.grails.org/grails/core" }
        maven { url "https://central.maven.org/maven2/"}
    }
    dependencies {
        classpath "org.grails:grails-gradle-plugin:$grailsGradlePluginVersion"
        classpath "org.grails.plugins:hibernate5:7.2.2"
        classpath "gradle.plugin.com.github.erdi.webdriver-binaries:webdriver-binaries-gradle-plugin:2.6"
        classpath "com.bertramlabs.plugins:asset-pipeline-gradle:3.3.4"
    }
}

version "0.1"
group "sso.testing"

apply plugin:"eclipse"
apply plugin:"idea"
apply plugin:"war"
apply plugin:"org.grails.grails-web"
apply plugin:"com.github.erdi.webdriver-binaries"
apply plugin:"com.bertramlabs.asset-pipeline"
apply plugin:"org.grails.grails-gsp"

repositories {
    maven { url "https://repo.grails.org/grails/core" }
    maven { url "https://central.maven.org/maven2/"}
}

configurations {
    developmentOnly
    runtimeClasspath {
        extendsFrom developmentOnly
    }
}

dependencies {
    ...
    implementation 'org.grails.plugins:spring-security-core:5.0.0-RC1'
    implementation 'io.github.grails-spring-security-saml:spring-security-saml:5.0.0-RC3'
    ...
}
```

application.groovy

```
// Added by the Spring Security Core plugin:
grails.plugin.springsecurity.userLookup.userDomainClassName = 'com.jeffwils.User'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'com.jeffwils.UserRole'
grails.plugin.springsecurity.authority.className = 'com.jeffwils.Role'
grails.plugin.springsecurity.requestMap.className = 'com.jeffwils.UserRole'
grails.plugin.springsecurity.securityConfigType = 'Requestmap'
grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	[pattern: '/',               access: ['permitAll']],
	[pattern: '/error',          access: ['permitAll']],
	[pattern: '/index',          access: ['permitAll']],
	[pattern: '/index.gsp',      access: ['permitAll']],
	[pattern: '/shutdown',       access: ['permitAll']],
	[pattern: '/assets/**',      access: ['permitAll']],
	[pattern: '/**/js/**',       access: ['permitAll']],
	[pattern: '/**/css/**',      access: ['permitAll']],
	[pattern: '/**/images/**',   access: ['permitAll']],
	[pattern: '/**/favicon.ico', access: ['permitAll']],
    [pattern: '/saml2/**',       access: ['permitAll']]
]

grails.plugin.springsecurity.filterChain.chainMap = [
	[pattern: '/assets/**',      filters: 'none'],
	[pattern: '/**/js/**',       filters: 'none'],
	[pattern: '/**/css/**',      filters: 'none'],
	[pattern: '/**/images/**',   filters: 'none'],
	[pattern: '/**/favicon.ico', filters: 'none'],
	[pattern: '/**',             filters: 'JOINED_FILTERS']
]
```

application.yml

```
grails:
    plugin:
        springsecurity:
            # optional: automatic redirect to SSO login
            # auth:
            #    loginFormUrl: '/saml2/authenticate/<insert_registrationId>'
            userLookup:
                userDomainClassName: 'com.jeffwils.User'
                authorityJoinClassName: 'com.jeffwils.UserRole'
            authority:
                className: 'com.jeffwils.Role'
            requestMap:
                className: 'com.jeffwils.UserRole'
            securityConfigType: 'Requestmap'
            controllerAnnotations:
                staticRules: [
                                [pattern: '/',               access: ['permitAll']],
                                [pattern: '/error',          access: ['permitAll']],
                                [pattern: '/index',          access: ['permitAll']],
                                [pattern: '/index.gsp',      access: ['permitAll']],
                                [pattern: '/shutdown',       access: ['permitAll']],
                                [pattern: '/assets/**',      access: ['permitAll']],
                                [pattern: '/**/js/**',       access: ['permitAll']],
                                [pattern: '/**/css/**',      access: ['permitAll']],
                                [pattern: '/**/images/**',   access: ['permitAll']],
                                [pattern: '/**/favicon.ico', access: ['permitAll']]
                             ]
            filterChain:
                chainMap: [
                            [pattern: '/assets/**',      filters: 'none'],
                            [pattern: '/**/js/**',       filters: 'none'],
                            [pattern: '/**/css/**',      filters: 'none'],
                            [pattern: '/**/images/**',   filters: 'none'],
                            [pattern: '/**/favicon.ico', filters: 'none'],
                            [pattern: '/**',             filters: 'JOINED_FILTERS']
                          ]
         providerNames: ['samlAuthenticationProvider', 'daoAuthenticationProvider', 'anonymousAuthenticationProvider']
         saml:
            active: true
            afterLoginUrl: '/'
            afterLogoutUrl: '/'
            loginNonce: false
            logoutNonce: false
            userGroupAttribute = 'roles'
            autoCreate:
                active: false # If you want the plugin to generate users in the DB as they are authenticated via SAML
                key: 'id'
                assignAuthorities: false # If you want the plugin to assign the authorities that come from the SAML message.
            metadata:
                defaultIdp: 'localhost:default:entityId'
                url: '/saml/metadata'
                providers:
                    ping: 'security/idp-local.xml'
                sp:
                    defaults:
                        entityID: 'test'
                        # for those who are upgrading from grails 4
                        # assertionConsumerService: {baseUrl}/saml/SSO
                        # singleLogoutService: {baseUrl}/saml/SingleLogout
                        signingKey: 'ping'
            keyManager:
                storeFile: "classpath:security/keystore.jks"
                storePass: 'nalle123'
                passwords:
                    ping: 'ping123'
```

# Keystore generation:

```
openssl pkcs12 -export -in cert-sso.pem -inkey server-key-sso.pem -name <signingKey> -out grails-app/conf/security/keystore.jks
```

# Detect if logged in via SSO

```
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
if (authentication instanceof Saml2Authentication) {
    url = "/logout/saml2" // change URL to global logout via saml2
}
```

# Login/Logout links with defaultIdp

```
<sec:loginLink class="nav-link"><g:message code="index.login.label"/></sec:loginLink>

<sec:logoutLink class="nav-link"><g:message code="index.logout.label"/></sec:logoutLink>
```

# Access SAML attributes via principal

```
grails:
    plugin:
        springsecurity:
            saml:
                userAttributeMappings:
                    username: 'urn:oid: ...'
                    email: 'urn:oid: ...'
                    fullname: 'urn:oid: ...'
```

```
class User implements Serializable {

    // ...
    
    String username
    String email
    String fullname

    // ...
}
```

```
class ProposalController {

    // ...

    def propose(Proposal proposal) {
        proposal.username = principal.username
        proposal.submitterEmail = principal.email
        proposal.submitterName = principal.fullname
        
        // ...
    }

    // ...
}
```
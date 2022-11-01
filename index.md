{% include_relative README.md %}

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
                        local:
                        securityProfile:
                        encryptionKey:
                        tlsKey:
                        requireArtifactResolveSigned:
                        requireLogoutRequestSigned:
                        requireLogoutResponseSigned:
```

Spring Security Core has now the concept of a RelyingPartyRegistrationReposity. A RelyingPartyRegistration must be created for each Service Provider and Identity Provider pair and each pair is uniquely identified by a registrationId which is identical to the registrationId specified in the providers property. This plugin automatically generates RelyingPartyregistrations for each IDP based on the provided XML IDP Metadata.

The entityID of the Service Provider is generated based on the pattern specified in `grails.plugins.springsecurity.saml.saml.metadata.sp.defaults.entityID` which is `{baseUrl}/saml2/service-provider-metadata/{registrationId}` by default.

The location specified in the AssertionConsumerService tag is now `{baseUrl}/login/saml2/sso/{registrationId}`.
The location specified in the SingleLogoutService tag is now `{baseUrl}/logout/saml2/sso/{registrationId}`.

Finally, the Service Provider needs to include the certificate specified by `grails.plugins.springsecurity.saml.saml.metadata.sp.defaults.signingKey`

The generated metadata files are available under `/saml2/service-provider-metadata/{registrationId}`.

Specifying both `assertionConsumerService` and `defaultIdp` will create a custom Filter at the Path `assertionConsumerService` which can only login to the IDP specified in `defaultIdp`. This is intended to allow an existing application to upgrade to the latest version of this plugin without having to re-register its metadata if all it does is integrate a single service provider with a single identity provider.

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

Warning: Some table or column names may conflict with existing SQL keywords such as 'USER' or 'PASSWORD' on postgres or other RDBMS. If neccessary these can be adjusted in the mapping block of your user domain class:

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


| Property | Syntax | Example Value | Description |
|--------|------|-------------|-----------|
| active | boolean | true | States whether or not SAML is active |
| afterLoginUrl | url string | '/' | Redirection Url in your application upon successful login from the IDP |
| afterLogoutUrl | url string | '/' | Redirection Url in your application upon successful logout from the IDP |
| userAttributeMappings | Map | [username:'funkyUserNameFromIDP'] | Allows Custom Mapping if both Application and IDP Attribute Names cannot be changed. |
| userGroupAttribute | String Value | 'memberOf' | Corresponds to the Role Designator in the SAML Assertion from the IDP |
| userGroupToRoleMapping | Map [Spring Security Role: Saml Assertion Role] | [ROLE_MY_APP_ROLE: 'CN=MYSAMLGROUP, OU=MyAppGroups, DC=myldap, DC=example, DC=com'] | This maps the Spring Security Roles in your application to the roles from the SAML Assertion.  Only roles in this Map will be resolved. |
| useLocalRoles | boolean | true | Determine a user's role based on the existing values in the local Spring Security tables. Will merge with additional roles loaded via `userGroupAttribute` and `userGroupToRoleMapping`. Defaults to `false`.
| autoCreate.active | boolean | false | If you want the plugin to generate users in the DB as they are authenticated via SAML
| autoCreate.key | domain class unique identifier | 'id' | if autoCreate active is true then this is the unique id field of the db table |
| autoCreate.assignAuthorities | boolean | false | If you want the plugin to insert the authorities that come from the SAML message into the UserRole Table. |
| metadata.providers | Map [registrationId: idp file reference] | [ping:"/pathtoIdpFile/myIdp.xml"] | Map of idp providers. Contain a registration id and reference to the idp xml file |
| metadata.defaultIdp | String | 'https://idp.example.org/idp/shibboleth' | the entityId of the default Idp from the ones listed in the metadata.provider map. If no entityId is given an IDP will be picked from the list automatically. |
| metadata.url | relative url | '/saml/metadata/{registrationId}' | url used to retrieve the SP metadata for your app to send to the IDP |
| metadata.sp.defaults.entityId | String Value |'http://myapp.example.com' | Identifier for the Service Provider |
| metadata.sp.defaults.signingKey | keystore alias | 'mykey' | For local entities alias of private key used to create signatures. The default private key is used when no value is provided. For remote identity providers defines an additional public key used to verify signatures. |
| keyManager.storeFile | file reference string |  "/mypath/mykeystore.jks" |
| keyManager.storePass | password string | 'changeit' | Keypass to keystore referenced in storeFile |
| keyManager.passwords | password map [private key registrationId:password] | [mykey:'changeit'] | Map of registration ids and passwords if private key in storeFile is password protected |

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
	[pattern: '/**/favicon.ico', access: ['permitAll']]
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
            userGroupAttribute = 'roles'
            autoCreate:
                active: false # If you want the plugin to generate users in the DB as they are authenticated via SAML
                key: 'id'
                assignAuthorities: false # If you want the plugin to assign the authorities that come from the SAML message.
            metadata:
                defaultIdp: 'localhost:default:entityId'
                # for those who are upgrading from grails 4
                # assertionConsumerService: {baseUrl}/saml/SSO
                # singleLogoutService: {baseUrl}/saml/SingleLogout
                url: '/saml/metadata'
                providers:
                    ping: 'security/idp-local.xml'
                sp:
                    defaults:
                        entityId: 'test'
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
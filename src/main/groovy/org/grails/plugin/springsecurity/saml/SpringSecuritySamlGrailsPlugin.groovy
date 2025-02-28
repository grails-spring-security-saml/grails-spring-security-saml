package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import grails.plugins.Plugin
import org.cryptacular.util.CertUtil
import org.cryptacular.util.KeyPairUtil
import org.springframework.core.io.Resource
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml2.core.Saml2X509Credential
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutRequestValidator
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutResponseValidator
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations
import org.springframework.security.saml2.provider.service.web.*
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter
import org.springframework.security.saml2.provider.service.web.authentication.logout.*
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.util.matcher.AndRequestMatcher
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

import javax.servlet.http.HttpServletRequest
import java.security.KeyStore
import java.security.KeyStore.PasswordProtection
import java.security.KeyStore.PrivateKeyEntry
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.util.function.Predicate

class SpringSecuritySamlGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    String grailsVersion = '3.3.0 > *'
    String author = 'Jeff Wilson'
    String authorEmail = 'jeffwilson70@gmail.com'
    String title = 'Spring Security Saml2 Plugin'
    String description = 'Grails 3 Saml2 Support for Spring Security plugin.'
    String documentation = 'https://jeffwils.github.io/grails-spring-security-saml/'
    String license = 'APACHE'
    //def organization = [name: 'Grails', url: 'http://www.grails.org/']
    def organization = [:]
    def issueManagement = [url: 'https://github.com/jeffwils/grails-spring-security-saml/issues']
    def scm = [url: 'https://github.com/jeffwils/grails-spring-security-saml']
    def profiles = ['web']

    def dependsOn = ['springSecurityCore' : '3.2.0 > *']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        'test/**',
        "grails-app/views/error.gsp",
        "UrlMappings",
        'docs/**',
        'scripts/PublishGithub.groovy'
    ]

    // Any additional developers beyond the author specified above.
    def developers = [[ name: "Alvaro Sanchez-Mariscal", email: "alvaro.sanchez@salenda.es" ], [ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ],[ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ], [ name: "Jeff Beck", email: "beckje01@gmail.com" ], [ name: "Sphoorti Acharya", email: "sphoortiacharya@gmail.com" ]]


    def registrations = []

    Closure doWithSpring() {
        {->
            def conf = SpringSecurityUtils.securityConfig
            if( !isActive( conf ) )
                return

            println 'Configuring Spring Security SAML ...'

            SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
            SpringSecurityUtils.registerLogoutHandler 'logoutHandler'
            SpringSecurityUtils.registerFilter 'saml2WebSsoAuthenticationFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
            SpringSecurityUtils.registerFilter 'saml2AuthenticationRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
            SpringSecurityUtils.registerFilter 'saml2LogoutRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
            SpringSecurityUtils.registerFilter 'saml2LogoutResponseFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
            SpringSecurityUtils.registerFilter 'relyingPartyLogoutFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 6

            requestCache(HttpSessionRequestCache)

            successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
                alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
                defaultTargetUrl = conf.saml.afterLoginUrl
                requestCache = ref('requestCache')
                redirectStrategy = ref('redirectStrategy')
            }

            logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
                defaultTargetUrl = conf.saml.afterLogoutUrl
            }

            def storePass = conf.saml.keyManager.storePass.toCharArray()
            def keystore = null
            if (conf.saml.keyManager.storeFile) {
                keystore = loadKeystore(getResource(conf.saml.keyManager.storeFile), storePass)
            }
            String signingKey = conf.saml.metadata.sp.defaults.signingKey
            String verificationKey = conf.saml.metadata.sp.defaults.verificationKey ?: signingKey

            log.debug "Dynamically defining bean metadata providers... "
            def providers = conf.saml.metadata.providers
            providers.each { registrationId, metadataLocation ->
                println "Registering registrationId ${registrationId} from ${metadataLocation}"
                registrations << registrationFromMetadata(conf, registrationId, metadataLocation, keystore)
            }

            // Retrieve UserDetails via SSO
            userDetailsService(SpringSamlUserDetailsService) {
                grailsApplication = grailsApplication
                authorityClassName = conf.authority.className
                authorityJoinClassName = conf.userLookup.authorityJoinClassName
                authorityNameField = conf.authority.nameField
                samlAutoCreateActive = conf.saml.autoCreate.active
                samlAutoAssignAuthorities = conf.saml.autoCreate.assignAuthorities
                samlAutoCreateKey = conf.saml.autoCreate.key
                samlUserAttributeMappings = conf.saml.userAttributeMappings
                samlUserGroupAttribute = conf.saml.userGroupAttribute
                samlUserGroupToRoleMapping = conf.saml.userGroupToRoleMapping
                userDomainClassName = conf.userLookup.userDomainClassName
            }

            // compatibility shim for UserDetailsService
            samlResponseAuthenticationConverter(SamlResponseAuthenticationConverter) {
                userDetailsService = ref('userDetailsService')
            }

            samlAuthenticationProvider(OpenSaml4AuthenticationProvider) {
                responseAuthenticationConverter = ref('samlResponseAuthenticationConverter')
            }

            authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
                redirectStrategy = ref('redirectStrategy')
                defaultFailureUrl = conf.saml.loginFailUrl ?: '/login/authfail?login_error=1'
                useForward = conf.failureHandler.useForward // false
                ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
                exceptionMappings = conf.failureHandler.exceptionMappings // [:]
                allowSessionCreation = conf.failureHandler.allowSessionCreation // true
            }
            redirectStrategy(PostAwareRedirectStrategy) {
                contextRelative = conf.redirectStrategy.contextRelative // false
            }

            sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)

            logoutHandler(SecurityContextLogoutHandler) {
                invalidateHttpSession = true
            }
            springSecurityService(SamlSecurityService) {
                config = conf
                authenticationTrustResolver = ref('authenticationTrustResolver')
                grailsApplication = grailsApplication
                passwordEncoder = ref('passwordEncoder')
                objectDefinitionSource = ref('objectDefinitionSource')
                userDetailsService = ref('userDetailsService')
                userCache = ref('userCache')
            }

            if (registrations.isEmpty()) {
                if (!conf.saml.metadata.hideProviderWarning) {
                    throw new IllegalArgumentException("No providers have been defined in the providers section (registrations), please define " +
                        "grails.plugin.springsecurity.saml.metadata.providers.{registrationId} = 'security/idp.xml' " +
                        "for at least one IDP or define a custom relyingPartyRegistrationRepository yourself " +
                        "and set grails.plugin.springsecurity.saml.metadata.hideProviderWarning = true to skip this warning.")
                }
            } else {
                // collection of identity and service provider pairs
                relyingPartyRegistrationRepository(InMemoryRelyingPartyRegistrationRepository, registrations)
            }

            relyingPartyRegistrationRepositoryResolver(DefaultRelyingPartyRegistrationResolver, ref('relyingPartyRegistrationRepository'))

            if (conf.saml.metadata.defaultIdp) {
                println "Activating default registration ${conf.saml.metadata.defaultIdp}"
                def defaultRegistrationId = (registrations
                    .find{ it.assertingPartyDetails.entityId == conf.saml.metadata.defaultIdp }?.registrationId
                    ?: conf.saml.metadata.defaultIdp)

                // force the use of registrationId specified by 'defaultIdp'
                defaultIdpRegistrationRepositoryResolver(DefaultRegistrationResolver) {
                    relyingPartyRegistrationResolver = ref('relyingPartyRegistrationRepositoryResolver')
                    defaultRegistration = defaultRegistrationId
                }
            }

            if (conf.saml.metadata.defaultIdp && conf.saml.metadata.sp.defaults.assertionConsumerService) {
                String loginProcessingUrl = null
                try {
                    loginProcessingUrl = new URL(conf.saml.metadata.sp.defaults.assertionConsumerService).getPath()
                } catch(MalformedURLException e) {
                    println "Failed to get path from URL ${conf.saml.metadata.sp.defaults.assertionConsumerService}"
                }
                if (loginProcessingUrl != null) {
                    defaultIdpAuthenticationConverter(Saml2AuthenticationTokenConverter, ref('defaultIdpRegistrationRepositoryResolver')) {
                        authenticationRequestRepository = ref('authenticationRequestRepository')
                    }

                    // IDP -> SP communication
                    defaultIdpSaml2WebSsoAuthenticationFilter(Saml2WebSsoAuthenticationFilter, ref('defaultIdpAuthenticationConverter'), loginProcessingUrl) {
                        authenticationRequestRepository = ref('authenticationRequestRepository')
                        authenticationManager = ref('authenticationManager')
                        sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                        authenticationSuccessHandler = ref('successRedirectHandler')
                        authenticationFailureHandler = ref('authenticationFailureHandler')
                    }
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2WebSsoAuthenticationFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 5
                }
            }

            securityTagLib(SamlTagLib) {
                springSecurityService = ref('springSecurityService')
                webExpressionHandler = ref('webExpressionHandler')
                webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
                grailsApplication = grailsApplication
            }

            contextResolver(DefaultSaml2AuthenticationRequestContextResolver, ref('relyingPartyRegistrationRepositoryResolver'))
            authenticationRequestRepository(HttpSessionSaml2AuthenticationRequestRepository)
            authenticationConverter(Saml2AuthenticationTokenConverter, ref('relyingPartyRegistrationRepositoryResolver')) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
            }

            openSamlMetadataResolver(OpenSamlMetadataResolver)

            def metadataUrl = conf.saml.metadata.url
            saml2MetadataFilter(Saml2MetadataFilter, ref('relyingPartyRegistrationRepositoryResolver'), ref('openSamlMetadataResolver')) {
                if (metadataUrl) {
                    if (!metadataUrl.contains("{registrationId}")) {
                        throw new IllegalArgumentException("grails.plugin.springsecurity.saml.metadata.url must contain {registrationId}")
                    }
                    requestMatcher = new AntPathRequestMatcher(metadataUrl)
                }
            }

            //authenticationRequestFactory(OpenSaml4AuthenticationRequestFactory)
            authenticationRequestResolver(OpenSaml4AuthenticationRequestResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            // IDP -> SP communication
            String loginProcessingUrl = "/login/saml2/sso/{registrationId}"
            saml2WebSsoAuthenticationFilter(Saml2WebSsoAuthenticationFilter, ref('authenticationConverter'), loginProcessingUrl) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
                authenticationManager = ref('authenticationManager')
                sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                authenticationSuccessHandler = ref('successRedirectHandler')
                authenticationFailureHandler = ref('authenticationFailureHandler')
            }

            // SP -> IDP communication
            // The login nonce transfers attributes from a previously authenticated session to the newly authenticated session
            saml2AuthenticationRequestFilter(Saml2WebSsoAuthenticationRequestFilter, ref('authenticationRequestResolver')) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
            }

            String logoutUrl = "/logout/saml2"
            String logoutResponseUrl = "/logout/saml2/slo";
            String logoutRequestUrl = "/logout/saml2/slo";

            logoutResponseValidator(OpenSamlLogoutResponseValidator)
            logoutResponseResolver(OpenSaml4LogoutResponseResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            logoutRequestRepository(HttpSessionLogoutRequestRepository)
            logoutRequestValidator(OpenSamlLogoutRequestValidator)
            logoutRequestResolver(OpenSaml4LogoutRequestResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            securityContextLogoutHandler(SecurityContextLogoutHandler)
            logoutNonceSecurityContextLogoutHandler(LogoutNonceSecurityContextLogoutHandler) {
                logoutNonceService = ref("logoutNonceService")
            }
            logoutSuccessEventPublishingLogoutHandler(LogoutSuccessEventPublishingLogoutHandler)

            samlLogoutHandlerFactory(LogoutHandlerListFactory,
                ref('securityContextLogoutHandler'),
                ref('logoutNonceSecurityContextLogoutHandler'),
                ref('logoutSuccessEventPublishingLogoutHandler'))

            samlLogoutHandlers(samlLogoutHandlerFactory: "getInstance")

            saml2LogoutRequestFilter(Saml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutRequestValidator'), ref('logoutResponseResolver'), ref("samlLogoutHandlers")) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutRequestUrl),
                    new ParameterRequestMatcher("SAMLRequest"))
            }

            saml2LogoutResponseFilter(Saml2LogoutResponseFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutResponseValidator'), ref('logoutSuccessHandler')) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutResponseUrl),
                    new ParameterRequestMatcher("SAMLResponse"))
                logoutRequestRepository = ref('logoutRequestRepository')
            }

            if (conf.saml.metadata.defaultIdp && conf.saml.metadata.sp.defaults.singleLogoutService) {
                def singleLogoutService = conf.saml.metadata.sp.defaults.singleLogoutService
                String defaultIdpLogoutResponseUrl = null
                try {
                    defaultIdpLogoutResponseUrl = new URL(singleLogoutService).getPath()
                } catch(MalformedURLException e) {
                    println "Failed to get path from URL ${singleLogoutService}"
                }
                if (defaultIdpLogoutResponseUrl != null) {
                    // IDP -> SP communication
                    defaultIdpSaml2LogoutRequestFilter(Saml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                            ref('logoutRequestValidator'), ref('logoutResponseResolver'), ref("samlLogoutHandlers")) {
                        logoutRequestMatcher = new AndRequestMatcher(
                            new AntPathRequestMatcher(defaultIdpLogoutResponseUrl),
                            new ParameterRequestMatcher("SAMLRequest"))
                    }

                    Boolean logoutNonceEnabled = conf.saml.logoutNonce ?: false
                    if (logoutNonceEnabled) {
                        // IDP -> SP communication
                        defaultIdpSaml2LogoutRequestFilter(LogoutNonceSaml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                                ref('logoutRequestValidator'), ref('logoutResponseResolver'), ref("samlLogoutHandlers")) {

                            logoutNonceService = ref('logoutNonceService')

                            logoutRequestMatcher = new AndRequestMatcher(
                                    new AntPathRequestMatcher(defaultIdpLogoutResponseUrl),
                                    new ParameterRequestMatcher("SAMLRequest"))
                        }
                    }

                    // IDP -> SP communication
                    defaultIdpSaml2LogoutResponseFilter(Saml2LogoutResponseFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                            ref('logoutResponseValidator'), ref('logoutSuccessHandler')) {
                        logoutRequestMatcher = new AndRequestMatcher(
                            new AntPathRequestMatcher(defaultIdpLogoutResponseUrl),
                            new ParameterRequestMatcher("SAMLResponse"))
                        logoutRequestRepository = ref('logoutRequestRepository')
                    }
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2LogoutRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 7
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2LogoutResponseFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 8
                }
            }

            logoutRequestSuccessHandler(Saml2RelyingPartyInitiatedLogoutSuccessHandler, ref('logoutRequestResolver')) {
                logoutRequestRepository = ref('logoutRequestRepository')
            }

            relyingPartyLogoutFilter(LogoutFilter, ref('logoutRequestSuccessHandler'), ref("samlLogoutHandlers")) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutUrl),
                    new Saml2RequestMatcher())
            }

            // login nonce augmented versions of the previously set up beans
            Boolean loginNonceEnabled = conf.saml.loginNonce ?: false
            if (loginNonceEnabled) {
                jsessionidCookieSameSiteSupplier(SamlCookieSameSiteSupplier)

                requestCache(LoginNonceRequestCache) {
                    loginNonceService = ref('loginNonceService')
                }

                // The login nonce transfers attributes from a previously authenticated session to the newly authenticated session
                loginNonceService(LoginNonceService) {
                    cookieExpiry = conf.saml.loginNonceExpiry ?: 30 * 60 // 30 minutes
                }
                authenticationRequestRepository(LoginNonceSaml2AuthenticationRequestRepository) {
                    loginNonceService = ref('loginNonceService')
                }

                authenticationRequestResolver(OpenSaml4AuthenticationRequestResolver, ref('relyingPartyRegistrationRepositoryResolver')) {
                    relayStateResolver = ref("relayStateResolver")
                }

                relayStateResolver(LoginNonceRelayStateResolver) {
                    loginNonceService = ref("loginNonceService")
                }
            }

            Boolean logoutNonceEnabled = conf.saml.logoutNonce ?: false
            if (logoutNonceEnabled) {
                logoutNonceService(LogoutNonceService)
                logoutRequestRepository(LogoutNonceLogoutRequestRepository) {
                    logoutNonceService = ref('logoutNonceService')
                }

                successRedirectHandlerOriginal(SavedRequestAwareAuthenticationSuccessHandler) {
                    alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
                    defaultTargetUrl = conf.saml.afterLoginUrl
                    requestCache = ref('requestCache')
                    redirectStrategy = ref('redirectStrategy')
                }

                successRedirectHandler(LogoutNonceAuthenticationSuccessHandler) {
                    logoutNonceService = ref('logoutNonceService')
                    authenticationSuccessHandler = ref('successRedirectHandlerOriginal')
                }

                saml2LogoutRequestFilter(LogoutNonceSaml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutRequestValidator'), ref('logoutResponseResolver'), ref("samlLogoutHandlers")) {

                    logoutNonceService = ref('logoutNonceService')

                    logoutRequestMatcher = new AndRequestMatcher(
                        new AntPathRequestMatcher(logoutRequestUrl),
                        new ParameterRequestMatcher("SAMLRequest"))
                }
            }

            println '...finished configuring Spring Security SAML'
        }
    }

    private static class Saml2RequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null) {
                return false;
            }
            return authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal;
        }

    }

    private static class ParameterRequestMatcher implements RequestMatcher {

        Predicate<String> test = Objects::nonNull;

        String name;

        ParameterRequestMatcher(String name) {
            this.name = name;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            return this.test.test(request.getParameter(this.name));
        }

    }

    KeyStore loadKeystore(resource, storePass) {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        resource.URL.withInputStream { is ->
            keystore.load(is, storePass)
        }
        return keystore
    }

    X509Certificate readCertificate(Resource resource) throws Exception {
        return resource.getInputStream().withCloseable {is ->
            return CertUtil.readCertificate(is)
        }
    }

    RSAPrivateKey readPrivateKey(Resource resource) throws Exception {
        return resource.getInputStream().withCloseable {is ->
            return KeyPairUtil.readPrivateKey(is)
        }
    }

    def registrationFromMetadata(conf, registrationId, metadataLocation, keystore) {

        String relyingPartyEntityId = conf.saml.metadata.sp.defaults.entityID ?: "{baseUrl}/saml2/service-provider-metadata/{registrationId}"
        String assertionConsumerServiceLocation = conf.saml.metadata.sp.defaults.assertionConsumerService ?: "{baseUrl}/login/saml2/sso/{registrationId}"
        String relyingSingleLogoutServiceLocation = conf.saml.metadata.sp.defaults.singleLogoutService ?: "{baseUrl}/logout/saml2/sso/{registrationId}"

        String signingKey = conf.saml.metadata.sp.defaults.signingKey

        Saml2X509Credential relyingPartySigningCredential

        if (conf.saml.keyManager.storeFile && keystore != null) {
            PrivateKeyEntry signingEntry
            if (conf.saml.keyManager.passwords) {
                def entryPass = conf.saml.keyManager.passwords[signingKey]
                if (entryPass) {
                    def passwordProtection = new PasswordProtection(entryPass.toCharArray())
                    signingEntry = (PrivateKeyEntry)keystore.getEntry(signingKey, passwordProtection)
                } else {
                    throw new IOException("Password for keystore entry ${signingKey} cannot be found at " +
                            "'grails.plugin.springsecurity.saml.keyManager.passwords.${signingKey}' in your application.yml.")
                }
            }
            if (signingEntry == null) {
                throw new IOException("Keystore entry ${signingKey} cannot be loaded from file '${conf.saml.keyManager.storeFile}'. " +
                        "Please check that the path configured in " +
                        "'grails.plugin.springsecurity.saml.keyManager.storeFile' in your application.yml is correct.")
            }

            relyingPartySigningCredential = new Saml2X509Credential(signingEntry.privateKey,
                    signingEntry.certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION)
        } else if (conf.saml.keyManager.privateKeyFile || conf.saml.keyManager.certificateFile) {

            Resource certificateFile = applicationContext.getResource(conf.saml.keyManager.certificateFile)
            Resource privateKeyFile = applicationContext.getResource(conf.saml.keyManager.privateKeyFile)

            if (!certificateFile.exists()) {
                throw new FileNotFoundException("Public key file '${conf.saml.keyManager.certificateFile}' configured " +
                        "in 'grails.plugin.springsecurity.saml.keyManager.certificateFile' could not be found.")
            }
            if (!privateKeyFile.exists()) {
                throw new FileNotFoundException("Private key file '${conf.saml.keyManager.privateKeyFile}' configured " +
                        "in 'grails.plugin.springsecurity.saml.keyManager.privateKeyFile' could not be found.")
            }

            X509Certificate publicKey = (X509Certificate)readCertificate(certificateFile)
            PrivateKey privateKey = (PrivateKey)readPrivateKey(privateKeyFile)

            relyingPartySigningCredential = new Saml2X509Credential(privateKey, publicKey,
                    Saml2X509Credential.Saml2X509CredentialType.SIGNING, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION)
        }

        if (!relyingPartySigningCredential) {
            throw new IOException("Neither the keystore nor PEM files could be loaded. Please configure either " +
                "'grails.plugin.springsecurity.saml.keyManager.storeFile' or 'grails.plugin.springsecurity.saml.keyManager.privateKeyFile' " +
                "and 'grails.plugin.springsecurity.saml.keyManager.certificateFile'.")
        }

        return RelyingPartyRegistrations.fromMetadataLocation(metadataLocation)
            .registrationId(registrationId)
            .entityId(relyingPartyEntityId)
            .assertionConsumerServiceLocation(assertionConsumerServiceLocation)
            .singleLogoutServiceLocation(relyingSingleLogoutServiceLocation)
            .signingX509Credentials((c) -> c.add(relyingPartySigningCredential))
            .decryptionX509Credentials((c) -> c.add(relyingPartySigningCredential))
            .build()
    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }

    private static boolean isActive(conf) {
        final PLUGIN_NOT_AVAILABLE = 'SAML plugin will not be available'
        if( !conf ) {
            // This is unlikely to ever occur due to default configs included in plugins,
            // but historically has always been checked, so keeping.
            println "There is no Spring Security config, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( !conf.active ) {
            println "Spring Security Core plugin is not active, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( !conf.saml.active ) {
            println "saml.active is not true, $PLUGIN_NOT_AVAILABLE."

            return false
        }

        true
    }
}

package org.grails.plugin.springsecurity.saml

import grails.plugins.*
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition
import org.jdom.Document
import org.jdom.input.SAXBuilder
import org.jdom.output.XMLOutputter
import org.jdom.output.Format
import org.springframework.core.io.ClassPathResource;
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.saml.SAMLEntryPoint
import org.springframework.security.saml.SAMLProcessingFilter
import org.springframework.security.saml.SAMLLogoutFilter
import org.springframework.security.saml.SAMLLogoutProcessingFilter
import org.springframework.security.saml.websso.WebSSOProfileOptions
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.saml.websso.WebSSOProfileImpl
import org.springframework.security.saml.websso.WebSSOProfileECPImpl
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl
import org.springframework.security.saml.processor.HTTPPostBinding
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding
import org.springframework.security.saml.processor.HTTPArtifactBinding
import org.springframework.security.saml.processor.HTTPSOAP11Binding
import org.springframework.security.saml.processor.HTTPPAOS11Binding
import org.springframework.security.saml.processor.SAMLProcessorImpl
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate
import org.springframework.security.saml.metadata.MetadataDisplayFilter
import org.springframework.security.saml.metadata.MetadataGenerator
import org.springframework.security.saml.metadata.CachingMetadataManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.key.JKSKeyManager
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider

import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.Filter;
import org.opensaml.core.Version;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.DefaultSaml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.core.Saml2X509Credential
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.KeyStore.PasswordProtection
import org.opensaml.security.x509.X509Support
import java.security.cert.X509Certificate
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter

import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.util.matcher.AndRequestMatcher
import javax.servlet.http.HttpServletRequest
import java.util.function.Predicate
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutRequestValidator;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;


//import org.springframework.security.core.Authentication;
//import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

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


    def providers = []

    Closure doWithSpring() {
        {->
            def conf = SpringSecurityUtils.securityConfig
            if( !isActive( conf ) )
                return

            println 'Configuring Spring Security SAML ...'

            /*
            //Due to Spring DSL limitations, need to import these beans as XML definitions
            xmlns context:"http://www.springframework.org/schema/context"
            context.'annotation-config'()
            context.'component-scan'('base-package': "org.springframework.security.saml")

            */
            SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
            /*
            SpringSecurityUtils.registerLogoutHandler 'logoutHandler'
            */
            SpringSecurityUtils.registerFilter 'saml2WebSsoAuthenticationFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
            SpringSecurityUtils.registerFilter 'saml2AuthenticationRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
            SpringSecurityUtils.registerFilter 'saml2LogoutRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
            SpringSecurityUtils.registerFilter 'saml2LogoutResponseFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
            /*
            -----
            logoutRequestSuccessHandler
            -----
            */

            successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
                alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
                defaultTargetUrl = conf.saml.afterLoginUrl
            }

            logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
                defaultTargetUrl = conf.saml.afterLogoutUrl
            }
            /*

            def idpSelectionPath = conf.saml.entryPoint.idpSelectionPath
            samlEntryPoint(SAMLEntryPoint) {
                filterProcessesUrl = conf.auth.loginFormUrl // '/saml/login'
                if (idpSelectionPath) {
                    idpSelectionPath = idpSelectionPath // '/index.gsp'
                }
                defaultProfileOptions = ref('webProfileOptions')
            }

            log.debug "Dynamically defining bean metadata providers... "
            def providerBeanName = "extendedMetadataDelegate"
            conf.saml.metadata.providers.each {k,v ->

                println "Registering metadata key: ${k} and value: $v"
                "${providerBeanName}"(ExtendedMetadataDelegate) { extMetaDataDelegateBean ->
                    filesystemMetadataProvider(FilesystemMetadataProvider) { bean ->
                        File resource = new File(v)
                        bean.constructorArgs = [resource]
                        parserPool = ref('parserPool')
                    }
                    extMetaDataDelegateBean.constructorArgs = [ref('filesystemMetadataProvider'), new ExtendedMetadata()]
                }
                providers << ref(providerBeanName)
            }
            // you can only define a single service provider configuration
            def spFile = conf.saml.metadata.sp.file
            def defaultSpConfig = conf.saml.metadata.sp.defaults
            if (spFile) {
                println "Loading the service provider metadata from ${spFile}..."
                spMetadata(ExtendedMetadataDelegate) { spMetadataBean ->
                    spMetadataProvider(FilesystemMetadataProvider) { spMetadataProviderBean ->
                        File spResource = new File(spFile)
                        spMetadataProviderBean.constructorArgs = [spResource]
                        parserPool = ref('parserPool')
                    }
                    //TODO consider adding idp discovery default
                    spMetadataDefaults(ExtendedMetadata) { extMetadata ->
                        local = defaultSpConfig."local"
                        alias = defaultSpConfig."alias"
                        securityProfile = defaultSpConfig."securityProfile"
                        signingKey = defaultSpConfig."signingKey"
                        encryptionKey = defaultSpConfig."encryptionKey"
                        tlsKey = defaultSpConfig."tlsKey"
                        requireArtifactResolveSigned = defaultSpConfig."requireArtifactResolveSigned"
                        requireLogoutRequestSigned = defaultSpConfig."requireLogoutRequestSigned"
                        requireLogoutResponseSigned = defaultSpConfig."requireLogoutResponseSigned"
                    }
                    spMetadataBean.constructorArgs = [ref('spMetadataProvider'), ref('spMetadataDefaults')]
                }
                providers << ref('spMetadata')
            }

            metadata(CachingMetadataManager) { metadataBean ->
                // At this point, due to Spring DSL limitations, only one provider
                // can be defined so just picking the first one
                metadataBean.constructorArgs = [providers.first()]
                providers = providers

                if (defaultSpConfig?."entityId") {
                    hostedSPName = defaultSpConfig?."entityId"
                } else {
                    if (defaultSpConfig?."alias") {
                        hostedSPName = defaultSpConfig?."alias"
                    }
                }
                if(conf.saml.metadata?.defaultIdp != '') {
                    defaultIDP = conf.saml.metadata?.defaultIdp
                }
            }

            */
            userDetailsService(SpringSamlUserDetailsService) {
                grailsApplication = grailsApplication //(GrailsApplication)ref('grailsApplication')
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

            samlResponseAuthenticationConverter(SamlResponseAuthenticationConverter) {
                userDetailsService = ref('userDetailsService')
            }

            samlAuthenticationProvider(OpenSamlAuthenticationProvider) {
                responseAuthenticationConverter = ref('samlResponseAuthenticationConverter')
            }
            /*samlAuthenticationProvider(GrailsSAMLAuthenticationProvider) {
                userDetails = ref('userDetailsService')
            }*/

            authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
                redirectStrategy = ref('redirectStrategy')
                defaultFailureUrl = conf.saml.loginFailUrl ?: '/login/authfail?login_error=1'
                useForward = conf.failureHandler.useForward // false
                ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
                exceptionMappings = conf.failureHandler.exceptionMappings // [:]
            }
            redirectStrategy(DefaultRedirectStrategy) {
                contextRelative = conf.redirectStrategy.contextRelative // false
            }
            sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)

            logoutHandler(SecurityContextLogoutHandler) {
                invalidateHttpSession = true
            }
            securityTagLib(SamlTagLib) {
                springSecurityService = ref('springSecurityService')
                webExpressionHandler = ref('webExpressionHandler')
                webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
            }
            springSecurityService(SamlSecurityService) {
                config = conf
                authenticationTrustResolver = ref('authenticationTrustResolver')
                grailsApplication = grailsApplication //(GrailsApplication)ref('grailsApplication')
                passwordEncoder = ref('passwordEncoder')
                objectDefinitionSource = ref('objectDefinitionSource')
                userDetailsService = ref('userDetailsService')
                userCache = ref('userCache')
            }
            //https://github.com/jeffwils/grails-spring-security-saml/issues/63
            //remove beans from SecurityFilterAutoConfiguration.java
            //by overriding them with an empty string
            /*springSecurityFilterChain(String, "")
            securityFilterChainRegistration(String, "")*/

            String registrationId = "simplesamlphp";
            String baseUrl = "https://tuorga-qa.rz.tu-bs.de:443"

            String loginProcessingUrl = "/saml2/sso/{registrationId}"
            //https://tuorga-qa.rz.tu-bs.de:443
            //"/saml2/sso/${registrationId}"
            // /saml2/authenticate/simplesamlphp

            //service provider
            String relyingPartyEntityId = conf.saml.metadata.sp.defaults.entityID
            String assertionConsumerServiceLocation = "https://tuorga-qa.rz.tu-bs.de:443/saml/SSO"
            //"${baseUrl}/saml2/sso/${registrationId}"

            def storePass = conf.saml.keyManager.storePass.toCharArray()
            String signingKey = conf.saml.metadata.sp.defaults.signingKey
            String verificationKey = conf.saml.metadata.sp.defaults.verificationKey ?: signingKey

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            getResource(conf.saml.keyManager.storeFile).URL.withInputStream { is ->
                keystore.load(is, storePass)
            }

            def signingEntry = (PrivateKeyEntry)keystore.getEntry(signingKey, new PasswordProtection(storePass))
            Saml2X509Credential relyingPartySigningCredential = new Saml2X509Credential(signingEntry.privateKey,
                signingEntry.certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION)

            //identity provider
            String assertingPartyEntityId = conf.saml.metadata.defaultIdp
            String singleSignOnServiceLocation = "https://sso.tu-bs.de/simplesaml/saml2/idp/SSOService.php"

            //def verificationEntry = (PrivateKeyEntry)keystore.getEntry(verificationKey, new PasswordProtection(storePass))
            X509Certificate verificationcertificate = X509Support.decodeCertificate("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")
            Saml2X509Credential assertingPartyVerificationCredential = new Saml2X509Credential(verificationcertificate,
                Saml2X509Credential.Saml2X509CredentialType.VERIFICATION)

            //TODO SUPPORT LOADING METADATA FROM XML
            RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId(registrationId)
                .entityId(relyingPartyEntityId)
                .assertionConsumerServiceLocation(assertionConsumerServiceLocation)
                .signingX509Credentials((c) -> c.add(relyingPartySigningCredential))
                .decryptionX509Credentials((c) -> c.add(relyingPartySigningCredential))
                .assertingPartyDetails((details) -> details
                        .entityId(assertingPartyEntityId)
                        .singleSignOnServiceLocation(singleSignOnServiceLocation)
                        .verificationX509Credentials((c) -> c.add(assertingPartyVerificationCredential)))
                .build()

            //user provided?
            relyingPartyRegistrationRepository(InMemoryRelyingPartyRegistrationRepository, [registration])

            relyingPartyRegistrationRepositoryResolver(DefaultRelyingPartyRegistrationResolver, ref('relyingPartyRegistrationRepository'))

            openSamlMetadataResolver(OpenSamlMetadataResolver)

            saml2MetadataFilter(Saml2MetadataFilter, ref('relyingPartyRegistrationRepositoryResolver'), ref('openSamlMetadataResolver'))

            authenticationConverter(Saml2AuthenticationTokenConverter, ref('relyingPartyRegistrationRepositoryResolver'))

            authenticationRequestRepository(HttpSessionSaml2AuthenticationRequestRepository)

            authenticationRequestFactory(OpenSamlAuthenticationRequestFactory)

            contextResolver(DefaultSaml2AuthenticationRequestContextResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            saml2WebSsoAuthenticationFilter(Saml2WebSsoAuthenticationFilter, ref('authenticationConverter'), loginProcessingUrl) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
                authenticationManager = ref('authenticationManager')
                sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                authenticationSuccessHandler = ref('successRedirectHandler')
                authenticationFailureHandler = ref('authenticationFailureHandler')
            }

            saml2AuthenticationRequestFilter(Saml2WebSsoAuthenticationRequestFilter, ref('contextResolver'), ref('authenticationRequestFactory')) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
            }

            String logoutUrl = "/logout";
            String logoutResponseUrl = "/logout/saml2/slo";
            String logoutRequestUrl = "/logout/saml2/slo";

            def logoutMatcher = AndRequestMatcher(
                new AntPathRequestMatcher(logoutUrl, "POST"),
                new Saml2RequestMatcher())

            def logoutRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(logoutRequestUrl),
                new ParameterRequestMatcher("SAMLRequest"))

            def logoutResponseMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(logoutResponseUrl),
                new ParameterRequestMatcher("SAMLResponse"))

            logoutResponseValidator(OpenSamlLogoutResponseValidator)
            logoutResponseResolver(OpenSaml3LogoutResponseResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            logoutRequestRepository(HttpSessionLogoutRequestRepository)
            logoutRequestValidator(OpenSamlLogoutRequestValidator)
            logoutRequestResolver(OpenSaml3LogoutRequestResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            LogoutHandler[] logoutHandlers = [
                new SecurityContextLogoutHandler(),
                new LogoutSuccessEventPublishingLogoutHandler()
            ].toArray(new LogoutHandler[2]);

            saml2LogoutRequestFilter(Saml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutRequestValidator'), ref('logoutResponseResolver'), logoutHandlers) {
                logoutRequestMatcher = logoutRequestMatcher
            }

            saml2LogoutResponseFilter(Saml2LogoutResponseFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutResponseValidator'), ref('logoutSuccessHandler')) {
                logoutRequestMatcher = logoutResponseMatcher
                logoutRequestRepository = ref('logoutRequestRepository')
            }

            logoutRequestSuccessHandler(Saml2RelyingPartyInitiatedLogoutSuccessHandler, ref('logoutRequestResolver'))

            relyingPartyLogoutFilter(LogoutFilter, ref('logoutRequestSuccessHandler'), logoutHandlers) {
                logoutRequestMatcher = logoutMatcher
            }

            /*public final class Saml2LogoutConfigurer<H extends HttpSecurityBuilder<H>>
            		extends AbstractHttpConfigurer<Saml2LogoutConfigurer<H>, H> {

            	@Override
            	public void configure(H http) throws Exception {
            		LogoutConfigurer<H> logout = http.getConfigurer(LogoutConfigurer.class);
            		if (logout != null) {
            			this.logoutHandlers = logout.getLogoutHandlers();
            			this.logoutSuccessHandler = logout.getLogoutSuccessHandler();
            		}
            	}
            }*/

            println '...finished configuring Spring Security SAML'
            //String filterProcessingUrl = "/saml2/authenticate/{registrationId}";
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

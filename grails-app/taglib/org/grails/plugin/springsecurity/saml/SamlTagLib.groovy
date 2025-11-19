package org.grails.plugin.springsecurity.saml

import grails.core.GrailsApplication
import grails.plugin.springsecurity.SecurityTagLib
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication

class SamlTagLib extends SecurityTagLib {

    static final String LOGOUT_SLUG = '/logout'
    static defaultEncodeAs = [taglib:'sec']
    GrailsApplication grailsApplication
    DefaultRegistrationResolver defaultIdpRegistrationRepositoryResolver

    /**
     * {@inheritDocs}
     */
    def loggedInUserInfo = { attrs, body ->
        String field = assertAttribute('field', attrs, 'loggedInUserInfo')

        def source = springSecurityService.authentication.details."${field}"

        if (source) {
            out << source.encodeAsHTML()
        }
        else {
            out << body()
        }
    }

    /**
     * {@inheritDocs}
     */
    def loginLink = { attrs, body ->
        def springSecurityConfig = grailsApplication.config.grails.plugin.springsecurity
        def contextPath = request.contextPath
        def url = springSecurityConfig.auth.loginFormUrl
        def selectIdp = attrs.remove('selectIdp')

        def samlEnabled = springSecurityConfig.saml.active
        if (samlEnabled) {
            def defaultRegistration = defaultIdpRegistrationRepositoryResolver.defaultRegistration
            url = "/saml2/authenticate/${selectIdp ?: defaultRegistration}"
        }

        def elementClass = generateClassAttribute(attrs)
        def elementId = generateIdAttribute(attrs)

        out << "<a href='${contextPath}${url}'${elementId}${elementClass}>${body()}</a>"
    }

    /**
     * {@inheritDocs}
     */
    def logoutLink = { attrs, body ->
        def contextPath = request.contextPath
        def local = attrs.remove('local')
        def springSecurityConfig = grailsApplication.config.grails.plugin.springsecurity
        def url = springSecurityConfig.logout.filterProcessesUrl

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof Saml2Authentication) {
            url = "/logout/saml2"
        }

        def elementClass = generateClassAttribute(attrs)
        def elementId = generateIdAttribute(attrs)

        out << """<a href='${contextPath}${url}${local?'?local=true':''}'${elementId}${elementClass}>${body()}</a>"""
    }

    private String generateIdAttribute(Map attrs) {
        def elementId = ""
        if (attrs.id) {
            elementId = " id=\'${attrs.id}\'"
        }
        elementId
    }

    private String generateClassAttribute(Map attrs) {
        def elementClass = ""
        if (attrs.class) {
            elementClass = " class=\'${attrs.class}\'"
        }
        elementClass
    }
}

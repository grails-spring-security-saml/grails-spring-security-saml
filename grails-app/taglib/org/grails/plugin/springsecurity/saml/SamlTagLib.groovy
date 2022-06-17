package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SecurityTagLib
import grails.util.Holders
import grails.core.GrailsApplication


class SamlTagLib extends SecurityTagLib {

    static final String LOGOUT_SLUG = '/logout'
    static defaultEncodeAs = [taglib:'sec']
    GrailsApplication grailsApplication

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
        def contextPath = request.contextPath
        def url = Holders.grailsApplication.config.grails.plugin.springsecurity.auth.loginFormUrl
        def selectIdp = attrs.remove('selectIdp')

        def samlEnabled = Holders.grailsApplication.config.grails.plugin.springsecurity.saml.active
        if (samlEnabled) {
            def defaultIdp = Holders.grailsApplication.config.grails.plugin.springsecurity.saml.metadata.defaultIdp
            url = "/saml2/authenticate/${selectIdp ?: defaultIdp}"
        }

        def elementClass = generateClassAttribute(attrs)
        def elementId = generateIdAttribute(attrs)

        out << "<a href='${url}'${elementId}${elementClass}>${body()}</a>"
    }

    /**
     * {@inheritDocs}
     */
    def logoutLink = { attrs, body ->
        def contextPath = request.contextPath
        def local = attrs.remove('local')
        def url = Holders.grailsApplication.config.grails.plugin.springsecurity.logout.filterProcessesUrl

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

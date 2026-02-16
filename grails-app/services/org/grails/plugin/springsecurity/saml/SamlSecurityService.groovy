package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.userdetails.GrailsUser
import groovy.util.logging.Slf4j

/**
 * A subclass of {@link SpringSecurityService} to replace {@link getCurrentUser()}
 * method. The parent implementation performs a database load, but we do not have
 * database users here, so we simply return the authentication details.
 *
 * @author alvaro.sanchez
 */
@Slf4j('logger')
class SamlSecurityService extends SpringSecurityService {
    SpringSamlUserDetailsService userDetailsService
    def userCache
    static transactional = false
    def config

    SpringSamlUserDetailsService getUserDetailsService() {
        return userDetailsService
    }

    void setUserDetailsService(SpringSamlUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService
    }

    Object getCurrentUser() {
        logger.debug("SamlSecurityService.getCurrentUser")
        if (!isLoggedIn()) {
            return null
        }
        def userDetails = getAuthentication().details
        if (config?.saml?.autoCreate?.active) {
            if (conf.saml.autoCreate.key instanceof String) {
                logger.debug("SamlSecurityService.getCurrentUser: lookup via autoCreate.key")
                userDetails = getCurrentPersistedUser(userDetails)
            } else if (conf.saml.autoCreate.key instanceof Boolean && !conf.saml.autoCreate.key) {
                logger.debug("SamlSecurityService.getCurrentUser: lookup via Grails Spring Security Core")
                userDetails = super.getCurrentUser()
            } else {
                throw new IllegalArgumentException("The configuration setting \"grails.plugin.springsecurity.saml.autoCreate.key\" " +
                    "must be a string or false.")
            }
        }
        return userDetails
    }

    private Object getCurrentPersistedUser(userDetails) {
        if (userDetails) {
            String className = config?.userLookup.userDomainClassName
            String userKey = config?.saml.autoCreate.key
            if (className && userKey) {
                Class<?> userClass = grailsApplication.getDomainClass(className)?.clazz
                return userClass."findBy${userKey.capitalize()}"(userDetails."$userKey")
            }
        } else { return null}
    }

    reactor.bus.Bus sendAndReceive(java.lang.Object obj, groovy.lang.Closure closure) {
        return null
    }
}

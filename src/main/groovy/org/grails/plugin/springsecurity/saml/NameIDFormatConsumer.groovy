package org.grails.plugin.springsecurity.saml


import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver

import java.util.function.Consumer

class NameIDFormatConsumer implements Consumer<OpenSaml4LogoutRequestResolver.LogoutRequestParameters> {

    @Override
    void accept(OpenSaml4LogoutRequestResolver.LogoutRequestParameters parameters) {
        String nameIdFormat = parameters.relyingPartyRegistration.nameIdFormat
        if (nameIdFormat != null) {
            parameters.logoutRequest.nameID.format = nameIdFormat
        }
    }
}

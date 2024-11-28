package org.grails.plugin.springsecurity.saml

import org.springframework.beans.factory.FactoryBean

class LogoutHandlerListFactory {
    Object[] beans

    LogoutHandlerListFactory(Object bean1, Object bean2, Object bean3) {
        this.beans = new Object[] {
            bean1, bean2, bean3
        }
    }

    Object getInstance() {
        return beans
    }
}

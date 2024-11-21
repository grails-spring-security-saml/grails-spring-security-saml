package org.grails.plugin.springsecurity.saml


import org.springframework.http.ResponseCookie
import org.springframework.security.saml2.core.Saml2ParameterNames
import org.springframework.security.saml2.core.Saml2X509Credential
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding
import spock.lang.Shared
import spock.lang.Specification

import javax.servlet.http.Cookie
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

class CookieLogoutRequestRepositorySpec extends Specification {

    @Shared
    CookieLogoutRequestRepository cookieLogoutRequestRepository
    @Shared
    RelyingPartyRegistration registration

    void setupSpec() {
        String cert = ("-----BEGIN CERTIFICATE-----\n"
        + "MIIEQTCCAymgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBkzEaMBgGA1UEAxMRTW9u\n"
        + "a2V5IE1hY2hpbmUgQ0ExCzAJBgNVBAYTAlVLMREwDwYDVQQIEwhTY290bGFuZDEQ\n"
        + "MA4GA1UEBxMHR2xhc2dvdzEcMBoGA1UEChMTbW9ua2V5bWFjaGluZS5jby51azEl\n"
        + "MCMGCSqGSIb3DQEJARYWY2FAbW9ua2V5bWFjaGluZS5jby51azAeFw0wNTAzMDYy\n"
        + "MzI4MjJaFw0wNjAzMDYyMzI4MjJaMIGvMQswCQYDVQQGEwJVSzERMA8GA1UECBMI\n"
        + "U2NvdGxhbmQxEDAOBgNVBAcTB0dsYXNnb3cxGzAZBgNVBAoTEk1vbmtleSBNYWNo\n"
        + "aW5lIEx0ZDElMCMGA1UECxMcT3BlbiBTb3VyY2UgRGV2ZWxvcG1lbnQgTGFiLjEU\n"
        + "MBIGA1UEAxMLTHVrZSBUYXlsb3IxITAfBgkqhkiG9w0BCQEWEmx1a2VAbW9ua2V5\n"
        + "bWFjaGluZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDItxZr07mm65ttYH7RMaVo\n"
        + "VeMCq4ptfn+GFFEk4+54OkDuh1CHlk87gEc1jx3ZpQPJRTJx31z3YkiAcP+RDzxr\n"
        + "AgMBAAGjggFIMIIBRDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIHgDALBgNV\n"
        + "HQ8EBAMCBeAwHQYDVR0OBBYEFG7mW1czzw4vFcL03+wUvvvPVFY8MIHABgNVHSME\n"
        + "gbgwgbWAFKt47K8QG4qbH8exJY8WKPIXmq02oYGZpIGWMIGTMRowGAYDVQQDExFN\n"
        + "b25rZXkgTWFjaGluZSBDQTELMAkGA1UEBhMCVUsxETAPBgNVBAgTCFNjb3RsYW5k\n"
        + "MRAwDgYDVQQHEwdHbGFzZ293MRwwGgYDVQQKExNtb25rZXltYWNoaW5lLmNvLnVr\n"
        + "MSUwIwYJKoZIhvcNAQkBFhZjYUBtb25rZXltYWNoaW5lLmNvLnVrggEAMDUGCWCG\n"
        + "SAGG+EIBBAQoFiZodHRwczovL21vbmtleW1hY2hpbmUuY28udWsvY2EtY3JsLnBl\n"
        + "bTANBgkqhkiG9w0BAQUFAAOCAQEAZ961bEgm2rOq6QajRLeoljwXDnt0S9BGEWL4\n"
        + "PMU2FXDog9aaPwfmZ5fwKaSebwH4HckTp11xwe/D9uBZJQ74Uf80UL9z2eo0GaSR\n"
        + "nRB3QPZfRvop0I4oPvwViKt3puLsi9XSSJ1w9yswnIf89iONT7ZyssPg48Bojo8q\n"
        + "lcKwXuDRBWciODK/xWhvQbaegGJ1BtXcEHtvNjrUJLwSMDSr+U5oUYdMohG0h1iJ\n"
        + "R+JQc49I33o2cTc77wfEWLtVdXAyYY4GSJR6VfgvV40x85ItaNS3HHfT/aXU1x4m\n"
        + "W9YQkWlA6t0blGlC+ghTOY1JbgWnEfXMmVgg9a9cWaYQ+NQwqA==\n"
        + "-----END CERTIFICATE-----")

        ByteArrayInputStream bais = new ByteArrayInputStream(cert.getBytes());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        def certificate = (X509Certificate) cf.generateCertificate(bais)

        String PRIVATE_KEY = ("-----BEGIN PRIVATE KEY-----\n"
        + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM7t8Ub1DP+B91NJ\n"
        + "nC45zqIvd1QXkQ5Ac1EJl8mUglWFzUyFbhjSuF4mEjrcecwERfRummASbLoyeMXl\n"
        + "eiPg7jvSaz2szpuV+afoUo9c1T+ORNUzq31NvM7IW6+4KhtttwbMq4wbbPpBfVXA\n"
        + "IAhvnLnCp/VyY/npkkjAid4c7RoVAgMBAAECgYBcCuy6kj+g20+G5YQp756g95oN\n"
        + "dpoYC8T/c9PnXz6GCgkik2tAcWJ+xlJviihG/lObgSL7vtZMEC02YXdtxBxTBNmd\n"
        + "upkruOkL0ElIu4S8CUwD6It8oNnHFGcIhwXUbdpSCr1cx62A0jDcMVgneQ8vv6vB\n"
        + "/YKlj2dD2SBq3aaCYQJBAOvc5NDyfrdMYYTY+jJBaj82JLtQ/6K1vFIwdxM0siRF\n"
        + "UYqSRA7G8A4ga+GobTewgeN6URFwWKvWY8EGb3HTwFkCQQDgmKtjjJlX3BotgnGD\n"
        + "gdxVgvfYG39BL2GnotSwUbjjce/yZBtrbcClfqrrOWWw7lPcX1d0v8o3hJfLF5dT\n"
        + "6NAdAkA8qAQYUCSSUwxJM9u0DOqb8vqjSYNUftQ9dsVIpSai+UitEEx8WGDn4SKd\n"
        + "V8kupy/gJlau22uSVYI148fJSCGRAkBz+GEHFiJX657YwPI8JWHQBcBUJl6fGggi\n"
        + "t0F7ibceOkbbsjU2U4WV7sHyk8Cei3Fh6RkPf7i60gxPIe9RtHVBAkAnPQD+BmND\n"
        + "By8q5f0Kwtxgo2+YkxGDP5bxDV6P1vd2C7U5/XxaN53Kc0G8zu9UlcwhZcQ5BljH\n"
        + "N24cUWZOo+60\n"
        + "-----END PRIVATE KEY-----")

        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PRIVATE_KEY));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }
        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(keySpec);

        registration = RelyingPartyRegistration.withRegistrationId("cookieTest")
            .assertingPartyDetails {
                it.entityId("entityId")
                it.singleSignOnServiceLocation("B")
            }
            .decryptionX509Credentials {it.add(
                Saml2X509Credential.decryption(privateKey, certificate))
            }
            .signingX509Credentials {it.add(
                Saml2X509Credential.signing(privateKey, certificate))
            }
            .singleLogoutServiceLocation("A")
            .entityId("entityId").build()
        def repository = new InMemoryRelyingPartyRegistrationRepository(registration)
        cookieLogoutRequestRepository = new CookieLogoutRequestRepository(repository)
    }

    // Test these scenarios:
    // parse an example cookie from JSON
    // generate an example JSON
    // generate and then parse

    void "Test get a cookie from a Saml2LogoutRequest"() {
        def saml2LogoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
            .id("identification:ABCD")
            .location("location:1234")
            .binding(Saml2MessageBinding.POST)
            .parameters { it -> it.putAll([
                (Saml2ParameterNames.SAML_REQUEST): "A.SAML_REQUEST",
                (Saml2ParameterNames.SAML_RESPONSE): "B.SAML_RESPONSE",
                (Saml2ParameterNames.RELAY_STATE): "C.RELAY_STATE",
                (Saml2ParameterNames.SIG_ALG): "D.SIG_ALG",
                (Saml2ParameterNames.SIGNATURE): "E.SIGNATURE",
                (Saml2ParameterNames.SAML_REQUEST): "F.SAML_REQUEST"
            ])}.build()

        when:"The index action is executed"
            ResponseCookie cookie = cookieLogoutRequestRepository.getSaml2LogoutRequestCookie(saml2LogoutRequest)

        then:"The model is correct"
            cookie != null
            cookie.name == CookieLogoutRequestRepository.COOKIE_NAME
            cookie.value == Base64.getEncoder().encodeToString("{\"id\":\"identification:ABCD\",\"location\":\"location:1234\",\"binding\":\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\",\"parameters\":{\"SigAlg\":\"D.SIG_ALG\",\"SAMLRequest\":\"F.SAML_REQUEST\",\"RelayState\":\"C.RELAY_STATE\",\"SAMLResponse\":\"B.SAML_RESPONSE\",\"Signature\":\"E.SIGNATURE\"},\"relyingPartyRegistrationId\":\"cookieTest\"}".getBytes())
            cookie.secure == true
            cookie.httpOnly == true
            cookie.sameSite == "None"
            cookie.path == "/"
    }

    void "Test get a Saml2LogoutRequest from a cookie"() {
        def cookieValue = Base64.getEncoder().encodeToString("{\"id\":\"identification:ABCD\",\"location\":\"location:1234\",\"binding\":\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\",\"parameters\":{\"SigAlg\":\"D.SIG_ALG\",\"SAMLRequest\":\"F.SAML_REQUEST\",\"RelayState\":\"C.RELAY_STATE\",\"SAMLResponse\":\"B.SAML_RESPONSE\",\"Signature\":\"E.SIGNATURE\"},\"relyingPartyRegistrationId\":\"cookieTest\"}".getBytes())
        def cookie = new Cookie(CookieLogoutRequestRepository.COOKIE_NAME, cookieValue)
        cookie.setSecure(true)
        cookie.setHttpOnly(true)
        cookie.setMaxAge(-1)
        cookie.setPath("/")

        when:"The index action is executed"
            def saml2LogoutRequest = cookieLogoutRequestRepository.getSaml2LogoutRequestFromCookie(cookie)

        then:"The model is correct"
            saml2LogoutRequest.id == "identification:ABCD"
            saml2LogoutRequest.location == "location:1234"
            saml2LogoutRequest.binding == Saml2MessageBinding.POST
            saml2LogoutRequest.parameters[Saml2ParameterNames.SAML_RESPONSE] == "B.SAML_RESPONSE"
            saml2LogoutRequest.parameters[Saml2ParameterNames.RELAY_STATE] == "C.RELAY_STATE"
            saml2LogoutRequest.parameters[Saml2ParameterNames.SIG_ALG] == "D.SIG_ALG"
            saml2LogoutRequest.parameters[Saml2ParameterNames.SIGNATURE] == "E.SIGNATURE"
            saml2LogoutRequest.parameters[Saml2ParameterNames.SAML_REQUEST] == "F.SAML_REQUEST"
            saml2LogoutRequest.relyingPartyRegistrationId == "cookieTest"
    }
}

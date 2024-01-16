package io.security.oauth2.springsecurityoauth2

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import javax.servlet.http.HttpServletRequest

class CustomOAuth2AuthorizationRequestResolver(
    private val clientRegistrationRepository: ClientRegistrationRepository,
    baseUri: String,
): OAuth2AuthorizationRequestResolver { // 조금 더 보안을 위해서 커스텀을 할 수 있다. PKCE를 하기 위해서는 필요로 한다.

    private val defaultResolver: DefaultOAuth2AuthorizationRequestResolver
    private val antPathMatcher: AntPathRequestMatcher
    private val REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId"
    private val DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
        .withPkce()

    init {
        antPathMatcher = AntPathRequestMatcher("$baseUri/{$REGISTRATION_ID_URI_VARIABLE_NAME}")
        defaultResolver = DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri)
    }

    override fun resolve(request: HttpServletRequest?): OAuth2AuthorizationRequest? {
        val registrationId: String? = resolveRegistrationId(request) // registration id를 가져온다.

        if(registrationId == "" || registrationId == null) // 만약 registration id가 없으면, 즉 비로그인 상태인 경우이다.
            return null // null을 리턴한다. null을 리턴하는 것을 쳐고보려고 했는데 방법을 못찾았음.. 이거는 그냥 숙련도 차이일지도?

        if(registrationId == "keycloakWithPKCE") { // PKCE = CSRF를 방지하고 인가 코드 주입 공격을 방어하기 위한 authorization code flow 확
            val oAuth2AuthorizationRequest = defaultResolver.resolve(request)
            return customResolve(oAuth2AuthorizationRequest, registrationId)
        }

        return defaultResolver.resolve(request)
    }

    override fun resolve(request: HttpServletRequest, clientRegistrationId: String): OAuth2AuthorizationRequest? {
        val registrationId: String? = resolveRegistrationId(request)

        if(registrationId == "" || registrationId == null)
            return null

        if(registrationId == "keycloakWithPKCE") {
            val oAuth2AuthorizationRequest = defaultResolver.resolve(request)
            return customResolve(oAuth2AuthorizationRequest, clientRegistrationId)
        }

        return defaultResolver.resolve(request)
    }

    private fun customResolve(
        oAuth2AuthorizationRequest: OAuth2AuthorizationRequest?,
        clientRegistrationId: String,

        ): OAuth2AuthorizationRequest {
        val extraMap = mutableMapOf<String, Any>()
        extraMap["customName1"] = "customValue1"
        extraMap["customName2"] = "customValue2"
        extraMap["customName3"] = "customValue3"

        val builder = OAuth2AuthorizationRequest.from(oAuth2AuthorizationRequest)
            .additionalParameters(extraMap)
        DEFAULT_PKCE_APPLIER.accept(builder)

        return builder.build()
    }

    private fun resolveRegistrationId(request: HttpServletRequest?): String? {
        if(antPathMatcher.matches(request)) {
            return antPathMatcher.matcher(request).variables[REGISTRATION_ID_URI_VARIABLE_NAME]
        }
        return ""
    }
}
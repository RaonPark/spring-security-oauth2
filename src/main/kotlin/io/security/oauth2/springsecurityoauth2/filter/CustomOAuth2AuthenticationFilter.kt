package io.security.oauth2.springsecurityoauth2.filter

import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import java.time.Clock
import java.time.Duration
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class CustomOAuth2AuthenticationFilter(
    private val oAuth2AuthorizedClientManager: DefaultOAuth2AuthorizedClientManager,
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository
): AbstractAuthenticationProcessingFilter(DEFAULT_FILTER_PROCESSING_URI) {
    companion object {
        const val DEFAULT_FILTER_PROCESSING_URI: String = "/oauth2Login/**"
    }

    private val clockSkew = Duration.ofSeconds(3600)
    private val clock = Clock.systemUTC()
    private var successHandler: OAuth2AuthorizationSuccessHandler? = null

    init {
        successHandler = OAuth2AuthorizationSuccessHandler { // sam
                authorizedClient: OAuth2AuthorizedClient, principal: Authentication, attributes: MutableMap<String, Any> ->
            oAuth2AuthorizedClientRepository.saveAuthorizedClient(
                authorizedClient, principal,
                attributes[HttpServletRequest::class.java.name] as HttpServletRequest,
                attributes[HttpServletResponse::class.java.name] as HttpServletResponse
            )
            println("authorizedClient = $authorizedClient")
            println("principal = $principal")
            println("attributes = $attributes")
        }

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler)
    }

    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        var authentication = SecurityContextHolder.getContext().authentication

        if(authentication == null) {
            authentication = AnonymousAuthenticationToken("anonymous", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))
        }

        val authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
            .principal(authentication)
            .attribute(HttpServletRequest::class.java.name, request)
            .attribute(HttpServletResponse::class.java.name, response)
            .build()

        val authorizedClient: OAuth2AuthorizedClient? = oAuth2AuthorizedClientManager.authorize(authorizeRequest)

        if(authorizedClient != null && hasTokenExpired(authorizedClient.accessToken) && authorizedClient.refreshToken != null) {
            oAuth2AuthorizedClientManager.authorize(authorizeRequest)
        }

        if(authorizedClient != null) {
            val oAuth2UserService = DefaultOAuth2UserService()
            val clientRegistration = authorizedClient.clientRegistration
            val accessToken = authorizedClient.accessToken
            val oAuth2UserRequest = OAuth2UserRequest(clientRegistration, accessToken)
            val oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest)

            val authorityMapper = SimpleAuthorityMapper()
            authorityMapper.setPrefix("SYSTEM_")
            val grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.authorities)

            val oAuth2AuthenticationToken = OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, clientRegistration.registrationId)

            SecurityContextHolder.getContext().authentication = oAuth2AuthenticationToken

            this.successHandler?.onAuthorizationSuccess(authorizedClient, oAuth2AuthenticationToken,
                createAttributes(request, response)
            )

            return oAuth2AuthenticationToken
        }

        return authentication
    }

    private fun hasTokenExpired(token: OAuth2Token): Boolean {
        return this.clock.instant().isAfter(token.expiresAt!!.minus(this.clockSkew))
    }

    private fun createAttributes(
        servletRequest: HttpServletRequest,
        servletResponse: HttpServletResponse
    ): Map<String, Any>? {
        val attributes: MutableMap<String, Any> = HashMap()
        attributes[HttpServletRequest::class.java.name] = servletRequest
        attributes[HttpServletResponse::class.java.name] = servletResponse
        return attributes
    }

}
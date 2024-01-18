package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.time.Clock
import java.time.Duration
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller
class LoginController @Autowired constructor(
    private val oAuth2AuthorizedClientManager: DefaultOAuth2AuthorizedClientManager,
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository
) {
    private val clockSkew = Duration.ofSeconds(3600)
    private val clock = Clock.systemUTC()
    @GetMapping("/oauth2Login")
    fun oauth2Login(model: Model, request: HttpServletRequest, response: HttpServletResponse): String {

        /**
         * 익명 사용자가 나오고(anonymousUser)
         * authorize grant type은 password가 된다.
         */
        val authentication = SecurityContextHolder.getContext().authentication

        val authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
            .principal(authentication)
            .attribute(HttpServletRequest::class.java.name, request)
            .attribute(HttpServletResponse::class.java.name, response)
            .build()

        val successHandler = OAuth2AuthorizationSuccessHandler { // sam
            authorizedClient: OAuth2AuthorizedClient, principal: Authentication, attributes: MutableMap<String, Any> ->
            oAuth2AuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal,
                attributes[HttpServletRequest::class.java.name] as HttpServletRequest,
                attributes[HttpServletResponse::class.java.name] as HttpServletResponse)

            println("authorizedClient=$authorizedClient")
            println("principal=$principal")
            println("attributes=$attributes")
        }

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler)

        val authorizedClient: OAuth2AuthorizedClient? = oAuth2AuthorizedClientManager.authorize(authorizeRequest)

        // 권한 부여 타입을 변경하지 않고 실행
        if(authorizedClient != null && hasTokenExpired(authorizedClient.accessToken) && authorizedClient.refreshToken != null) {
            oAuth2AuthorizedClientManager.authorize(authorizeRequest)
        }

        // 권한 부여 타입을 변경하고 실행 refresh_token 방식으로 설정된다.
        if(authorizedClient != null && hasTokenExpired(authorizedClient.accessToken) && authorizedClient.refreshToken != null) {
            // 새로운 ClientRegistration값
            val clientRegistration = ClientRegistration.withClientRegistration(authorizedClient.clientRegistration)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build()

            val oAuth2AuthorizedClient = OAuth2AuthorizedClient(clientRegistration, authorizedClient.principalName, authorizedClient.accessToken,
                authorizedClient.refreshToken)

            val authorizeRequest2 = OAuth2AuthorizeRequest
                .withAuthorizedClient(oAuth2AuthorizedClient)
                .principal(authentication)
                .attribute(HttpServletRequest::class.java.name, request)
                .attribute(HttpServletResponse::class.java.name, response)
                .build()

            oAuth2AuthorizedClientManager.authorize(authorizeRequest2)
        }

        model.addAttribute("accessToken", authorizedClient?.accessToken?.tokenValue)
        model.addAttribute("refreshToken", authorizedClient?.refreshToken?.tokenValue)

        return "home"
    }

    private fun hasTokenExpired(token: OAuth2Token): Boolean {
        return this.clock.instant().isAfter(token.expiresAt!!.minus(this.clockSkew))
    }

    @GetMapping("/logout")
    fun logout(authentication: Authentication, request: HttpServletRequest, response: HttpServletResponse): String {
        val logoutHandler = SecurityContextLogoutHandler()
        logoutHandler.logout(request, response, authentication)

        return "redirect:/"
    }
}
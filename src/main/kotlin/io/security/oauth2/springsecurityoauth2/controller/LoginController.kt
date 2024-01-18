package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
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
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller
class LoginController @Autowired constructor(
    private val oAuth2AuthorizedClientManager: DefaultOAuth2AuthorizedClientManager,
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository
) {
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

        model.addAttribute("authorizedClient", authorizedClient?.accessToken?.tokenValue)

        return "home"
    }

    @GetMapping("/logout")
    fun logout(authentication: Authentication, request: HttpServletRequest, response: HttpServletResponse): String {
        val logoutHandler = SecurityContextLogoutHandler()
        logoutHandler.logout(request, response, authentication)

        return "redirect:/"
    }
}
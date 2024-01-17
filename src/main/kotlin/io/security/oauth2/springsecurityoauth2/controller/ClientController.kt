package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import javax.servlet.http.HttpServletRequest

@Controller
class ClientController @Autowired constructor(
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository,
    private val oAuth2AuthorizedClientService: OAuth2AuthorizedClientService
) {

    // AuthorizedClient 가 생성되었다는 의미
    @GetMapping("/client")
    fun client(request: HttpServletRequest, model: Model): String {
        val authentication = SecurityContextHolder.getContext().authentication
        val clientRegistrationId = "keycloak"

        val authorizedClient1 =
            oAuth2AuthorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistrationId, authentication, request)

        val authorizedClient2 =
            oAuth2AuthorizedClientService.loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistrationId, authentication.name)

        val accessToken = authorizedClient1.accessToken

        val oAuth2UserService = DefaultOAuth2UserService()
        val oAuth2User = oAuth2UserService.loadUser(OAuth2UserRequest(authorizedClient1.clientRegistration, accessToken)) // 실제로 인가서버 소통 이후에 유저 객체 반환

        val authenticationToken = OAuth2AuthenticationToken(oAuth2User, listOf(SimpleGrantedAuthority("ROLE_USER")),
            authorizedClient1.clientRegistration.registrationId) // 인증객체

        SecurityContextHolder.getContext().authentication = authenticationToken // 인증 객체에 넣어야 스프링 시큐리티에서 인증을 했다고 확인

        model.addAttribute("accessToken", accessToken.tokenValue)
        model.addAttribute("refreshToken", authorizedClient1.refreshToken)
        model.addAttribute("principalName", oAuth2User.name)
        model.addAttribute("clientName", authorizedClient1.clientRegistration.clientName)

        return "client"
    }
}
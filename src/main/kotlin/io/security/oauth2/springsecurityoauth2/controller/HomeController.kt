package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import javax.servlet.http.HttpServletRequest

@Controller
class HomeController @Autowired constructor(
    private val oAuth2AuthorizedClientService: OAuth2AuthorizedClientService,
    private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository
) {
    @GetMapping("/home")
    fun home(oAuth2AuthenticationToken: OAuth2AuthenticationToken, model: Model, request: HttpServletRequest): String {
        val authorizedClient = oAuth2AuthorizedClientService
            .loadAuthorizedClient<OAuth2AuthorizedClient>("keycloak", oAuth2AuthenticationToken.name)

        val authorizedClient2 = oAuth2AuthorizedClientRepository
            .loadAuthorizedClient<OAuth2AuthorizedClient>("keycloak", oAuth2AuthenticationToken, request)

        model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken)
        model.addAttribute("accessToken", authorizedClient.accessToken.tokenValue)
        model.addAttribute("refreshToken", authorizedClient.refreshToken?.tokenValue)
        return "home"
    }
}
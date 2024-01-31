package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HomeController {
    @GetMapping("/api/user")
    fun user(authentication: Authentication, @AuthenticationPrincipal oAuth2User: OAuth2User): Authentication {
        println("authentication = $authentication, oAuth2User = $oAuth2User")
        return authentication
    }

    @GetMapping("/api/oidc")
    fun oidc(authentication: Authentication, @AuthenticationPrincipal oidcUser: OidcUser): Authentication {
        println("authentication = $authentication, oAuth2User = $oidcUser")
        return authentication
    }
}
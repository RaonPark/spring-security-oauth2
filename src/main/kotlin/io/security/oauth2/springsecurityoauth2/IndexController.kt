package io.security.oauth2.springsecurityoauth2

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
class IndexController @Autowired constructor(
    private val clientRegistrationRepository: ClientRegistrationRepository
) {
    @GetMapping("/")
    fun index(): String {
        return "index"
    }

    @GetMapping("/user")
    fun user(accessToken: String): OAuth2User {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")
        val oAuth2AccessToken = OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX)

        val oAuth2UserRequest = OAuth2UserRequest(clientRegistration, oAuth2AccessToken)
        val defaultOAuth2UserService = DefaultOAuth2UserService()
        val oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest)

        return oAuth2User
    }

    @GetMapping("/oidc")
    fun oidc(accessToken: String, idToken: String): OAuth2User {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")
        val oAuth2AccessToken = OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX)

        val idTokenClaims = mutableMapOf<String, Any>()
        idTokenClaims[IdTokenClaimNames.ISS] = "http://localhost:8081/realms/oauth2"
        idTokenClaims[IdTokenClaimNames.SUB] = "OIDC0"
        idTokenClaims["preferred_username"] = "user"

        val oidcIdToken = OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims)

        val oidcUserRequest = OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcIdToken)
        val oidcUserService = OidcUserService()
        val oidcUser = oidcUserService.loadUser(oidcUserRequest)

        return oidcUser
    }

    @GetMapping("/securityUser")
    fun securityUser(authentication: Authentication): OAuth2User {
//        val authentication1 = SecurityContextHolder.getContext().authentication as OAuth2AuthenticationToken
        val authentication2 = authentication as OAuth2AuthenticationToken
        val oAuth2User = authentication2.principal as OAuth2User
        return oAuth2User
    }

    @GetMapping("/oAuth2User")
    fun oAuth2User(@AuthenticationPrincipal oAuth2User: OAuth2User) {
        print("oAuth2User = $oAuth2User")
    }

    @GetMapping("/oidcUser")
    fun oidcUser(@AuthenticationPrincipal oidcUser: OidcUser) {
        print("oidcUser = $oidcUser")
    }
}
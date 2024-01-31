package io.security.oauth2.springsecurityoauth2.service

import io.security.oauth2.springsecurityoauth2.model.GoogleUser
import io.security.oauth2.springsecurityoauth2.model.KeycloakUser
import io.security.oauth2.springsecurityoauth2.model.NaverUser
import io.security.oauth2.springsecurityoauth2.model.ProviderUser
import io.security.oauth2.springsecurityoauth2.repository.UserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service

@Service
abstract class AbstractOAuth2UserService {

    @set: Autowired
    lateinit var userRepository: UserRepository
    @set: Autowired
    lateinit var userService: UserService

    protected fun providerUser(clientRegistration: ClientRegistration, oAuth2User: OAuth2User): ProviderUser? {
        when (clientRegistration.registrationId) {
            "keycloak" -> {
                return KeycloakUser(oAuth2User, clientRegistration)
            }
            "google" -> {
                return GoogleUser(oAuth2User, clientRegistration)
            }
            "naver" -> {
                return NaverUser(oAuth2User, clientRegistration)
            }
        }

        return null
    }

    protected fun register(providerUser: ProviderUser, userRequest: OAuth2UserRequest) {
        val user = userRepository.findByUsername(providerUser.getUsername())

        if(user == null) {
            val registrationId = userRequest.clientRegistration.registrationId
            userService.register(registrationId, providerUser)
        } else {
            println("user = $user")
        }
    }
}
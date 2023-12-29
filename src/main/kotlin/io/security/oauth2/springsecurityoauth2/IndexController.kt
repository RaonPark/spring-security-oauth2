package io.security.oauth2.springsecurityoauth2

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class IndexController @Autowired constructor(
    private val clientRegistrationRepository: ClientRegistrationRepository
) {

    @GetMapping("/")
    fun index(): String {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")

        val clientId = clientRegistration.clientId
        print(clientId)

        val redirectUri = clientRegistration.redirectUri
        print(redirectUri)

        return "index"
    }
}
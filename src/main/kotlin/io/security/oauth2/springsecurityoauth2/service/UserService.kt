package io.security.oauth2.springsecurityoauth2.service

import io.security.oauth2.springsecurityoauth2.model.ProviderUser
import io.security.oauth2.springsecurityoauth2.model.User
import io.security.oauth2.springsecurityoauth2.repository.UserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class UserService @Autowired constructor(
    private val userRepository: UserRepository
) {
    fun register(registrationId: String, providerUser: ProviderUser) {
        val user = User(
            registrationId = registrationId,
            id = providerUser.getId(),
            username = providerUser.getUsername(),
            password = providerUser.getPassword(),
            email = providerUser.getEmail(),
            provider = providerUser.getProvider(),
            authorities = providerUser.getAuthorities())

        userRepository.register(user)
    }
}
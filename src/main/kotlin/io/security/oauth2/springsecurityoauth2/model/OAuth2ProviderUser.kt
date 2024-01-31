package io.security.oauth2.springsecurityoauth2.model

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.user.OAuth2User
import java.util.Collections
import java.util.UUID

abstract class OAuth2ProviderUser (
    private val attributes: Map<String, Any>,
    private val oAuth2User: OAuth2User,
    private val clientRegistration: ClientRegistration
): ProviderUser {
    override fun getPassword(): String {
        return UUID.randomUUID().toString()
    }

    override fun getEmail(): String {
        return getAttributes()["email"] as String
    }

    override fun getAuthorities(): MutableList<out GrantedAuthority> {
        return oAuth2User.authorities.toMutableList()
    }

    override fun getProvider(): String {
        return clientRegistration.registrationId
    }

    override fun getAttributes(): Map<String, Any> {
        return attributes
    }
}
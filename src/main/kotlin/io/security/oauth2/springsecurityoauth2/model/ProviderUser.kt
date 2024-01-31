package io.security.oauth2.springsecurityoauth2.model

import org.springframework.security.core.GrantedAuthority

interface ProviderUser {
    fun getId(): String
    fun getUsername(): String
    fun getPassword(): String
    fun getEmail(): String
    fun getProvider(): String
    fun getAuthorities(): MutableList<out GrantedAuthority>
    fun getAttributes(): Map<String, Any>
}
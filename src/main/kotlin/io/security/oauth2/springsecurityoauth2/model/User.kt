package io.security.oauth2.springsecurityoauth2.model

import org.springframework.security.core.GrantedAuthority

data class User(
    val registrationId: String,
    val id: String,
    val username: String,
    val password: String,
    val provider: String,
    val email: String,
    val authorities: MutableList<out GrantedAuthority>,
)
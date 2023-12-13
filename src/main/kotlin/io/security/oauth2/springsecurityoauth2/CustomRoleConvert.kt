package io.security.oauth2.springsecurityoauth2

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import java.util.*
import java.util.stream.Collectors

class CustomRoleConvert : Converter<Jwt, Collection<GrantedAuthority>> {

    private val PREFIX = "ROLE_"

    override fun convert(source: Jwt): Collection<GrantedAuthority>? {
        val scope = source.getClaimAsString("scope")
        val realmAccess = source.getClaimAsMap("realm_access")

        val authorities1 = scope.split(" ")
            .map { roleName -> PREFIX + roleName }
            .map { SimpleGrantedAuthority(it) }
            .toMutableList()

        val authorities2 = (realmAccess["roles"] as List<String>)
            .map { roleName -> PREFIX + roleName }
            .map { SimpleGrantedAuthority(it) }
            .toList()

        authorities1.addAll(authorities2)
        return authorities1
    }
}
package io.security.oauth2.springsecurityoauth2.config

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import java.util.*

class CustomAuthorityMapper : GrantedAuthoritiesMapper {
    companion object {
        private const val PREFIX: String = "ROLE_"
    }
    override fun mapAuthorities(authorities: Collection<GrantedAuthority>): Set<GrantedAuthority> {
        val mapped = HashSet<GrantedAuthority>(authorities.size)
        for (authority in authorities) {
            mapped.add(mapAuthority(authority.authority))
        }
        return mapped
    }

    private fun mapAuthority(name: String): GrantedAuthority {
        var scope = name

        if(name.lastIndexOf(".") > 0) {
            val index = name.lastIndexOf(".")
            scope = "SCOPE_${name.substring(index + 1)}"
        }

        if(!name.startsWith(PREFIX)) {
            scope = "$PREFIX$scope"
        }

        return SimpleGrantedAuthority(scope)
    }
}

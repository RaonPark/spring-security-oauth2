package io.security.oauth2.springsecurityoauth2

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer

class CustomSecurityConfigurer: AbstractHttpConfigurer<CustomSecurityConfigurer, HttpSecurity>() {

    private var isSecure: Boolean = false

    override fun init(builder: HttpSecurity?) {
        super.init(builder)
        println {"init method started.."}
    }

    override fun configure(builder: HttpSecurity?) {
        super.configure(builder)
        println {"configure method started.."}
        if(isSecure) {
            println {"http is required"}
        } else {
            println {"http is optional"}
        }
    }

    fun setFlag(isSecure: Boolean): CustomSecurityConfigurer  {
        this.isSecure = isSecure
        return this
    }
}

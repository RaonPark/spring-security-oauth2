package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class IndexController {
    @GetMapping("/")
    @Suppress("UNCHECKED_CAST")
    fun index(model: Model, authentication: Authentication?, @AuthenticationPrincipal oAuth2User: OAuth2User?): String {
        val oAuth2AuthenticationToken = authentication as OAuth2AuthenticationToken?
        if(oAuth2AuthenticationToken != null) {
            val attributes = oAuth2User?.attributes!!
            var name = attributes["name"] as String?

            if (oAuth2AuthenticationToken.authorizedClientRegistrationId == "naver") {
                name = (attributes["response"] as Map<String, Any>)["name"] as String
            }

            model.addAttribute("user", name)
        }
        return "index"
    }
}
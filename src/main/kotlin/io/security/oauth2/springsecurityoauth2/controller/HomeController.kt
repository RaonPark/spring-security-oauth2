package io.security.oauth2.springsecurityoauth2.controller

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class HomeController {
    @GetMapping("/home")
    fun home(): String {
        return "home"
    }
}
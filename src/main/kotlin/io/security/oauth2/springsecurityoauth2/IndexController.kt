package io.security.oauth2.springsecurityoauth2

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class IndexController {
    @GetMapping("/")
    fun index(): String {
        return "index"
    }

    @GetMapping("/home")
    fun home(): String {
        return "home"
    }
}
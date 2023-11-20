package io.security.oauth2.springsecurityoauth2.macrsa.controller

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.RequestEntity
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import java.net.URI

@RestController
class IndexController {
    @GetMapping("/")
    fun index(): String {
        return "index"
    }

    @GetMapping("/api/user")
    fun user(authentication: Authentication, @AuthenticationPrincipal principal: Jwt): Authentication {
        val authenticationToken = authentication as JwtAuthenticationToken
        val sub = authenticationToken.tokenAttributes["sub"]
        val email = authenticationToken.tokenAttributes["email"]
        val scope = authenticationToken.tokenAttributes["scope"]

        val sub1 = principal.getClaimAsString("sub")
        val token = principal.tokenValue

        val restTemplate = RestTemplate()
        val headers = HttpHeaders()
        headers.add("Authorization", "Bearer $token")
        val request = RequestEntity<String>(headers, HttpMethod.GET, URI("http://localhost:8082"))
//        val response = restTemplate.exchange(request, String::class.java)
//        val body = response.body

        return authentication
    }
}
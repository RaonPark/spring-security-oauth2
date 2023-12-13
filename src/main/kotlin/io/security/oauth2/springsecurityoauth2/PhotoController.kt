package io.security.oauth2.springsecurityoauth2

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class PhotoController {
    @GetMapping("/photos/1")
    fun photo1(): Photo {
        return Photo("user1", "1", "Photo 1 title", "Photo is nice")
    }

    @GetMapping("/photos/2")
    @PreAuthorize("hasAnyAuthority('SCOPE_photo')")
    fun photo2(): Photo {
        return Photo("user2", "2", "Photo 2 title", "Photo is good")
    }

    @GetMapping("/photos/3")
    @PreAuthorize("hasAnyAuthority('ROLE_default-roles-oauth2')")
    fun photo3(): Photo {
        return Photo("user3", "3", "Photo 3 title", "Photo is beauty")
    }
}
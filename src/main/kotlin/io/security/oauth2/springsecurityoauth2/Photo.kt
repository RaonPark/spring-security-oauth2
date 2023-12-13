package io.security.oauth2.springsecurityoauth2

data class Photo(
    val userId: String,
    val photoId: String,
    val photoTitle: String,
    val photoDescription: String,
)
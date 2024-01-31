package io.security.oauth2.springsecurityoauth2.repository

import io.security.oauth2.springsecurityoauth2.model.User
import org.springframework.stereotype.Repository

@Repository
class UserRepository {
    private val users = mutableMapOf<String, Any>()

    fun findByUsername(username: String): User? {
        if(users.containsKey("username")) {
            return users["username"] as User
        }
        return null
    }

    fun register(user: User) {
        if(users.containsKey(user.username)) {
            return;
        }
        users[user.username] = user
    }
}
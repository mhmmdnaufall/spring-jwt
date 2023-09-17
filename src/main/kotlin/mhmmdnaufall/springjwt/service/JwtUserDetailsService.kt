package mhmmdnaufall.springjwt.service

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class JwtUserDetailsService : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        if (username == "mhmmdnaufall") {
            return User(username, "\$2a\$10\$zBWUQH1I/3u.ubGVs2nzSuaM5wARCTxRJVnQG3kwxHcU3kk1OAqMC", mutableListOf())

        } else {
            throw UsernameNotFoundException("User not found with username : $username")
        }
    }
}
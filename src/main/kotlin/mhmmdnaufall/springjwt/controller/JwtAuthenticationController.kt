package mhmmdnaufall.springjwt.controller

import mhmmdnaufall.springjwt.config.JwtTokenUtil
import mhmmdnaufall.springjwt.model.JwtRequest
import mhmmdnaufall.springjwt.model.JwtResponse
import mhmmdnaufall.springjwt.service.JwtUserDetailsService
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.lang.Exception

@RestController
@CrossOrigin
class JwtAuthenticationController(
        private val authenticationManager: AuthenticationManager,
        private val jwtTokenUtil: JwtTokenUtil,
        private val userDetailsService: JwtUserDetailsService
) {

    @PostMapping("/authenticate")
    fun createAuthenticationToken(
            @RequestBody authenticationRequest: JwtRequest
    ): ResponseEntity<JwtResponse> = with(authenticationRequest) {

        authenticate(username, password)
        val userDetails = userDetailsService.loadUserByUsername(username)
        val token = jwtTokenUtil.generateToken(userDetails)

        ResponseEntity.ok(JwtResponse(token))
    }

    private fun authenticate(username: String, password: String) {
        try {
            authenticationManager.authenticate(UsernamePasswordAuthenticationToken(username, password))
        } catch (e: DisabledException) {
            throw Exception("USER_DISABLED", e)
        } catch (e: BadCredentialsException) {
            throw Exception("INVALID_CREDENTIALS", e)
        }
    }

}
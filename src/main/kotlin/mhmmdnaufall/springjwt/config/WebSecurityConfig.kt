package mhmmdnaufall.springjwt.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class WebSecurityConfig(
        private val jwtUserDetailsService: UserDetailsService,
        private val jwtAuthenticationEntryPoint: JwtAuthenticationEntryPoint,
        private val jwtRequestFilter: JwtRequestFilter,
) {

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationManager(authConfig: AuthenticationConfiguration): AuthenticationManager {
        return authConfig.authenticationManager
    }

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        return http
                // we don't need CSRF for this example
                .csrf { it.disable() }
                .authorizeHttpRequests { auth ->
                    auth
                            .requestMatchers("/authenticate").permitAll()
                            .anyRequest().authenticated()

                }
                .authenticationProvider(daoAuthenticationProvider())
                .exceptionHandling {
                    it.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                }
                // make sure we use stateless session; session won't be used to
                // store user's state.
                .sessionManagement {
                    it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                }
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter::class.java)
                .build()

    }

    @Bean
    fun daoAuthenticationProvider(): DaoAuthenticationProvider = DaoAuthenticationProvider().apply {
        // to inform where to load user for matching credentials
        // Use BCryptPasswordEncoder
        setUserDetailsService(jwtUserDetailsService)
        setPasswordEncoder(passwordEncoder())
    }

}
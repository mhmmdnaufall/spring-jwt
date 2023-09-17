package mhmmdnaufall.springjwt.config

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.io.Serializable
import java.util.Date

@Component
class JwtTokenUtil : Serializable {

    @Value("\${jwt.secret}")
    private lateinit var jwtSecret: String

    // retrieve username from jwt token
    fun getUsernameFromToken(token: String): String {
        return getClaimFromToken(token, Claims::getSubject)
    }

    // retrieve expiration date from jwt token
    fun getExpirationDateFromToken(token: String): Date {
        return getClaimFromToken(token, Claims::getExpiration)
    }

    fun <T> getClaimFromToken(token: String, claimsResolver: (Claims) -> T): T {
        val claims = getAllClaimsFromToken(token)
        return claimsResolver(claims)
    }

    // for retrieving any information from token we will need the secret key
    private fun getAllClaimsFromToken(token: String): Claims {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.toByteArray()))
                .build()
                .parseClaimsJws(token)
                .body
    }

    // check if the token has expired
    private fun isTokenExpired(token: String): Boolean {
        val expiration = getExpirationDateFromToken(token)
        return expiration.before(Date())
    }

    // generate token for user
    fun generateToken(userDetails: UserDetails): String {
        val claims = mutableMapOf<String, Any>()
        return doGenerateToken(claims, userDetails.username)
    }

    /**
     * while creating the token:
     * 1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID.
     * 2. Sign the JWT using the HS512 algorithm and secret key.
     * 3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
     * 	    compaction of the JWT to a URL-safe string
     */
    private fun doGenerateToken(claims: MutableMap<String, Any>, subject: String): String {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(
                        Date(System.currentTimeMillis())
                )
                .setExpiration(
                        Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)
                )
                .signWith(Keys.hmacShaKeyFor(jwtSecret.toByteArray()), SignatureAlgorithm.HS512)
                .compact()
    }

    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        val username = getUsernameFromToken(token)
        return (username == userDetails.username) && (!isTokenExpired(token))
    }

    companion object {
        private const val serialVersionUID = 1L

        const val JWT_TOKEN_VALIDITY = 5 * 60 * 60
    }

}
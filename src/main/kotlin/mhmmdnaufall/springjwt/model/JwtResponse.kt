package mhmmdnaufall.springjwt.model

import java.io.Serializable

data class JwtResponse(
        val jwtToken: String
) : Serializable {

    companion object {
        private const val serialVersionUID = 1L
    }

}
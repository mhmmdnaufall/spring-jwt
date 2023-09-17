package mhmmdnaufall.springjwt.model

import java.io.Serializable

data class JwtRequest(
        val username: String,
        val password: String
) : Serializable {

    // need default constructor for JSON Parsing
    constructor() : this("", "")

    companion object {
        private const val serialVersionUID = 1L
    }

}
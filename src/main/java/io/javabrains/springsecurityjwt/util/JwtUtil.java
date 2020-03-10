package io.javabrains.springsecurityjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// Allows to create new JWT object
// Lookup username in JWT
// Lookup expireAt in JWT
@Service
public class JwtUtil {
    // You need to have a secret key for SHA 256 encryption.
    private String SECRET_KEY = "secret";

    // CREATION ********************************************************************************************************
    // Main method****, create JWT
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        // Jwts object is not there on the latest version of libs**
        return Jwts.builder()
                .setClaims(claims) // set claims
                .setSubject(subject) // The person who has authenticated successfuly.
                .setIssuedAt(new Date(System.currentTimeMillis())) // Set creation date.
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Set expiration date. Set it to 10 hours from now.
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Set encryption method
                .compact();
    }

    // *****************************************************************************************************************

    // READ JWT INFO ***************************************************************************************************
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date()); // Check JWT expire date is before now.
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // *****************************************************************************************************************

}

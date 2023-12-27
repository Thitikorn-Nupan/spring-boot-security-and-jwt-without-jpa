package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/*
    The JwtTokenUtil is responsible(รับผิดชอบ) for performing JWT operations
    *** like creation and validation.
    It makes use of the io.jsonwebtoken.Jwts for achieving this.
// @Component
*/
public class JwtTokenUtil { //  Serializable
    // private static final long serialVersionUID = -2550185165626007488L;
    public static final long JWT_TOKEN_VALIDITY = 24 * 60 * 60 * 1000; // 24 hour
    @Value("${jwt.secret}")
    private String secret;
    private Logging logging;


    public JwtTokenUtil() {

        logging = new Logging(JwtTokenUtil.class);

    }


    // validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        logging.logBack.info("validateToken() works");
        final String username = getUsernameFromToken(token);
        if (username.equals(userDetails.getUsername()) && !isTokenExpired(token)) {
            logging.logBack.info("User exists");
            return true;
        } else {
            logging.logBack.warn("User do not exists");
            return false;
        }
    }

    // retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    // **
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver
                .apply(claims);
    }

    // retrieve any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts
                .parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }


    // check if the token has expired (v. หมดอายุแล้ว)
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration
                .before(new Date());
    }

    // retrieve expiration(การหมดอายุ) date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token,
                Claims::getExpiration);
    }

    // generate token for user
    public String generateToken(UserDetails userDetails) {
        logging.logBack.info("generateToken() works");
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(
                claims,
                userDetails.getUsername()
        );
    }
    private String doGenerateToken(Map<String, Object> claims, String subject) {
       /*
           Here, the doGenerateToken() method creates a JSON Web Token
        */
        logging.logBack.info("doGenerateToken() works");
        // issue (v. ออก)
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(subject) // Subject is combination of the username
                .setIssuedAt(new Date()) // The token is issued at the current date and time
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)) // The token should expire after 24 hours
                .signWith(SignatureAlgorithm.HS512, secret) // The token is signed using a secret key, which you can specify in the application.properties file or from system environment variable
                .compact();
    }

}

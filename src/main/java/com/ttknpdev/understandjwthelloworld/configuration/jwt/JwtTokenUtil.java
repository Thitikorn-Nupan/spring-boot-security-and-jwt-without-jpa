package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
    The JwtTokenUtil is responsible(รับผิดชอบ) for performing JWT operations *** like creation and validation.
    It makes use of the io.jsonwebtoken.Jwts for achieving this.
*/
public class JwtTokenUtil { //  Serializable

    // private static final long serialVersionUID = -2550185165626007488L;
    @Value("${jwt.validity}")
    private Long JWT_TOKEN_VALIDITY; // 1 hour
    @Value("${jwt.secret}")
    private String JWT_SECRET_KEY;
    private final Logging logging;


    public JwtTokenUtil() {
        logging = new Logging(JwtTokenUtil.class);
    }


    // validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        logging.logBack.info("validateToken() method works");
        final String username = getUsernameFromToken(token);
        if (username.equals(userDetails.getUsername()) && !isTokenExpired(token)) {
            logging.logBack.debug("User exists and validated");
            return true;
        } else {
            logging.logBack.debug("User do not exists");
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
                .setSigningKey(JWT_SECRET_KEY)
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
        logging.logBack.info("generateToken() method works");
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userDetails.getUsername()); // claim
        claims.put("roles", userDetails.getAuthorities());
        return doGenerateToken(
                claims,
                userDetails.getUsername() // subject
        );
    }

    // Here, the doGenerateToken() method creates a JSON Web Token
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        logging.logBack.info("doGenerateToken() works");
        // issue (v. ออก)
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(subject) // Subject is combination of the username
                .setIssuedAt(new Date()) // The token is issued at the current date and time
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY)) // The token should expire after 24 hours
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET_KEY) // The token is signed using a secret key, which you can specify in the application.properties file or from system environment variable
                .compact();
        /*
        payload look like
        {
          "sub": "Admin",
          "roles": [
            {
              "authority": "ROLE_ADMIN"
            }
          ],
          "exp": 1748056338,
          "iat": 1748052738,
          "username": "Admin"
        }
        */
    }

}

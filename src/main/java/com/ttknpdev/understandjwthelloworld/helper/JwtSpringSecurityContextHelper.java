package com.ttknpdev.understandjwthelloworld.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;

// Very perfect user didn't need pass token always on own just get it with SecurityContextHolder
public abstract class JwtSpringSecurityContextHelper {

    private static final Logger log = LoggerFactory.getLogger(JwtSpringSecurityContextHelper.class);

    private static UsernamePasswordAuthenticationToken getAuthenticationFromContext() {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        if (usernamePasswordAuthenticationToken == null) {
             log.debug("UsernamePasswordAuthenticationToken is null on security context");
        }

        return usernamePasswordAuthenticationToken;
    }

    public static WebAuthenticationDetails getWebAuthenticationDetails() {
        return (WebAuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
    }

    public static Object getPrincipal() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    public static Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) SecurityContextHolder.getContext().getAuthentication().getAuthorities();
    }

    /*public static Boolean isTokenExpired() {
        AuthenticationManager jwtAuthenticateToken = getAuthenticationFromContext();
        final Date expiration = jwtAuthenticateToken.getExpirationFromToken(jwtAuthenticateToken.getToken());
        return expiration
                .before(new Date());
    }

    public static Date getExpirationDate() {
        JwtAuthenticateToken jwtAuthenticateToken = getAuthenticationFromContext();
        return jwtAuthenticateToken.getExpirationFromToken(jwtAuthenticateToken.getToken());
    }

    public static Date getIssueDate() {
        JwtAuthenticateToken jwtAuthenticateToken = getAuthenticationFromContext();
        return jwtAuthenticateToken.getIssueFromToken(jwtAuthenticateToken.getToken());
    }

    public static Object getPrincipal() {
        // JwtAuthenticateToken jwtAuthenticateToken = getAuthenticationFromContext();
        return getAuthenticationFromContext().getPrincipal();
    }

    public static Claims getClaim() {
        return getAuthenticationFromContext().getClaim();
    }*/

    /*public static Boolean validateToken(String token,String username) {
        JwtAuthenticateToken jwtAuthenticateToken = getAuthenticationFromContext();
        final String subject = jwtAuthenticateToken.getSubjectFromToken(token);
        log.debug("subject : {} user : {}", subject,username);
        return ( subject.equals(username) && !isTokenExpired(token) );
    }*/




}
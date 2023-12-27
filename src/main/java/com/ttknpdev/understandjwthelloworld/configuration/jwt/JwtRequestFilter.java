package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import com.ttknpdev.understandjwthelloworld.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/*
    The JwtRequestFilter extends the Spring Web Filter OncePerRequestFilter class.
    For any incoming request this Filter class gets executed.
    It checks if the request has a valid JWT token.
    If it has a valid JWT Token then it sets the Authentication in the context,
    to specify that the current user is authenticated.
// @Component
*/
// Here, this filter class extends the OncePerRequestFilter class to guarantee(v. รับประกัน) a single execution per request.
public class JwtRequestFilter extends OncePerRequestFilter {

    private JwtUserDetailsService jwtUserDetailsService;
    private JwtTokenUtil jwtTokenUtil;
    private Logging logging;
    @Autowired
    public JwtRequestFilter(@Qualifier("detailsService") JwtUserDetailsService jwtUserDetailsService,
                            @Qualifier("tokenUtil") JwtTokenUtil jwtTokenUtil) {
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        logging = new Logging(JwtRequestFilter.class);
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        logging.logBack.info("doFilterInternal() works");
        final String REQUEST_TOKEN_FROM_HEADER = request.getHeader("Authorization"); // name for header. you can use Postman to specify this part (setting header)
        /*
            How does it work ?
            * Retrieve the username by parsing the Bearer Token and subsequently search for the corresponding user information in the database. (assume)
            * Verify the authenticity of the JWT.
            * Generate an Authentication object using the provided username and password, and subsequently store it in the SecurityContextHolder.
        */
        String username = null;
        String jwtToken = null;

        // JWT Token is in the form "Bearer <token>". Remove Bearer word and get
        // only the Token
        if ((REQUEST_TOKEN_FROM_HEADER != null) && REQUEST_TOKEN_FROM_HEADER.startsWith("Bearer ")) {

            jwtToken = REQUEST_TOKEN_FROM_HEADER.substring(7); // get token only 7 element
            // logging.logBack.info("jwtToken stores "+jwtToken);

            try {

                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                logging.logBack.info("username "+username+" has token "+jwtToken);

            } catch (IllegalArgumentException e) {

                logging.logBack.warn("Unable to get JWT Token");

            } catch (ExpiredJwtException e) {

                logging.logBack.warn("JWT Token has expired");

            }

        } else {

            logging.logBack.warn("JWT Token does not begin with Bearer String Or null");

        }

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set authentication
            boolean validateToken = jwtTokenUtil.validateToken(jwtToken , userDetails);
            if ( validateToken ) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                );

                usernamePasswordAuthenticationToken.setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(request)
                );

                // After setting the Authentication in the context, we specify
                // that the current user is authenticated.
                // So it passes the Spring Security Configurations successfully
                SecurityContextHolder
                        .getContext()
                        .setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        chain.doFilter(request, response);
    }

}

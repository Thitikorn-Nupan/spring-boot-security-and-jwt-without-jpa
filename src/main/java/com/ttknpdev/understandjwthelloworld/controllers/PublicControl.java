package com.ttknpdev.understandjwthelloworld.controllers;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtTokenUtil;
import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtUserDetailsService;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;


import com.ttknpdev.understandjwthelloworld.entities.LoginRequest;
import  com.ttknpdev.understandjwthelloworld.entities.JwtResponse;
/**
    Expose a POST API /authenticate using the JwtAuthenticationController.
    The POST API gets username and password in the body- Using Spring Authentication Manager
    *** we authenticate the username and password. If the credentials are valid,
    *** a JWT token is created using the JWTTokenUtil and provided to the client.
*/
@RestController
@RequestMapping(value = "/jwt")
public class PublicControl {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtUserDetailsService userDetailsService;
    private final Logging logging;

    @Autowired
    public PublicControl(AuthenticationManager authenticationManager,
                         @Qualifier("tokenUtil") JwtTokenUtil jwtTokenUtil,
                         @Qualifier("detailsService") JwtUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
        logging = new Logging(PublicControl.class);
    }

    // method for creating new user and new token
    @PostMapping(value = "/login")
    public ResponseEntity<JwtResponse> createAuthenticationToken(@RequestBody LoginRequest loginRequest) throws Exception {

        logging.logBack.info("http://localhost:8080/jwt/authentication is accessed (Public API)");

        final UserDetails USER_DETAILS = userDetailsService.loadUserByUsername(loginRequest.getUsername()); // retrieve the user from database
        String token = null;
        if (USER_DETAILS != null && BCrypt.checkpw(loginRequest.getPassword(), USER_DETAILS.getPassword())) {
            logging.logBack.debug("Authentication Successful");
            token = jwtTokenUtil.generateToken(USER_DETAILS);
            // ** only auth password
            authenticateOnlyByPasswordEncoder( USER_DETAILS , loginRequest.getPassword());
            // ** auth password and set security context
            // authenticateByPasswordEncoderAndSeSecurityContext(USER_DETAILS, loginRequest.getPassword());
        } else {
            logging.logBack.debug("Authentication Failed");
        }
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new JwtResponse(token));
    }


    private void authenticateOnlyByPasswordEncoder(UserDetails userDetails, String passwordAsText) throws Exception {
        try {
            // set authenticationManager
            // now SecurityContextHolder.getContext().getAuthentication() != null true
            Authentication authentication = authenticationManager.authenticate(
                            // Note when you have bean as PasswordEncoder it will auto decode you when you set => private Object credentials;
                            new UsernamePasswordAuthenticationToken(userDetails,passwordAsText)
            );

            logging.logBack.debug("principal {}",authentication.getPrincipal());

            /*
                Authentication authenticationMakeSure =  SecurityContextHolder.getContext().getAuthentication();
                logging.logBack.debug("principal (from context) {}", authenticationMakeSure.getPrincipal());
            */
        } catch (DisabledException e) {
            throw new Exception("User disabled", e.getCause());
        } catch (BadCredentialsException e) {
            // If password is not correct it will find this exception
            logging.logBack.debug("Invalid credentials (Your password is invalid) {}",e.getMessage());
            throw new Exception("Invalid credentials (Your password is invalid)", e.getCause());
        }
    }

    // Not working well
    private void authenticateByPasswordEncoderAndSeSecurityContext(UserDetails userDetails, String passwordAsText) throws Exception {
        try {
            // set authenticationManager
            // now SecurityContextHolder.getContext().getAuthentication() != null true
            Authentication authentication = authenticationManager.authenticate(
                    // Note when you have bean as PasswordEncoder it will auto decode you when you set => private Object credentials;
                    new UsernamePasswordAuthenticationToken(userDetails,passwordAsText)
            );

            logging.logBack.debug("principle {}",authentication.getPrincipal());


            SecurityContextHolder.getContext().setAuthentication(authentication);
            // *** Just remember you have to only set SecurityContextHolder.getContext() on doFilterInternal method

            // only work this class
            logging.logBack.debug("principle (context) {}",SecurityContextHolder.getContext().getAuthentication().getPrincipal());


        } catch (DisabledException e) {
            throw new Exception("User disabled", e.getCause());
        } catch (BadCredentialsException e) {
            // If password is not correct it will find this exception
            logging.logBack.debug("Invalid credentials (Your password is invalid) {}",e.getMessage());
            throw new Exception("Invalid credentials (Your password is invalid)", e.getCause());
        }
    }

}

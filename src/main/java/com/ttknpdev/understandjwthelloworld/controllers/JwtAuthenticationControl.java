package com.ttknpdev.understandjwthelloworld.controllers;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtTokenUtil;
import com.ttknpdev.understandjwthelloworld.service.JwtUserDetailsService;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;


import com.ttknpdev.understandjwthelloworld.entities.JwtRequest;
import  com.ttknpdev.understandjwthelloworld.entities.JwtResponse;
/*
    Expose a POST API /authenticate using the JwtAuthenticationController.
    The POST API gets username and password in the body- Using Spring Authentication Manager
    we authenticate the username and password. If the credentials are valid,
    a JWT token is created using the JWTTokenUtil and provided to the client.
*/
@RestController
@RequestMapping(value = "/jwt")
public class JwtAuthenticationControl {
    private AuthenticationManager authenticationManager;
    private JwtTokenUtil jwtTokenUtil;
    private JwtUserDetailsService userDetailsService;
    private Logging logging;
    @Autowired
    public JwtAuthenticationControl(AuthenticationManager authenticationManager,
                                    @Qualifier("tokenUtil") JwtTokenUtil jwtTokenUtil,
                                    @Qualifier("detailsService") JwtUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
        logging = new Logging(JwtAuthenticationControl.class);
    }

    /* method for creating new user and new token */
    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {

        logging.logBack.info("http://localhost:8080/jwt/authentication is accessed (Public API)");


        authenticate( authenticationRequest.getUsername() , authenticationRequest.getPassword() );

        final UserDetails USER_DETAILS = userDetailsService.loadUserByUsername(authenticationRequest.getUsername()); // retrieve the user from database

        final String TOKEN = jwtTokenUtil.generateToken(USER_DETAILS);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new JwtResponse(TOKEN));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(username, password)
                    );
        } catch (DisabledException e) {

            throw new Exception("User disabled", e.getCause());

        } catch (BadCredentialsException e) {

            /* If username and password is not correct it will find this exception */
            throw new Exception("Invalid credentials", e.getCause());

        }
    }
}

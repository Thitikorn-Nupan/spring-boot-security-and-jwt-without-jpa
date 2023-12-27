package com.ttknpdev.understandjwthelloworld.service;

import com.ttknpdev.understandjwthelloworld.configuration.jwt.JwtTokenUtil;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
/*
  JWTUserDetailsService implements the Spring Security UserDetailsService interface.
  It overrides the loadUserByUsername for fetching user details from the database using the username.
  The Spring Security Authentication Manager calls this method for getting the user details from the database
  when authenticating the user details provided by the user.
  Here we are getting the user details from a hardcoded User List.
// @Service
*/
public class JwtUserDetailsService implements UserDetailsService { // UserDetailsService is an interface that retrieves the user’s authentication
    private Logging logging;
    private final String  USERNAME_PASSWORD_DEMO[] = { // assume this is on your database
            "ttknpde-v" ,
            "$2a$10$tSwLP1aRNz6PpV.BWdpaducGAJaNBAcxX3pebldS1TbB.ZPFKux.S"
            /*
               it is Bcrypt Hash
               can covert any string to Bcrypt by web (has many web for building it)
            */
    };

    public JwtUserDetailsService() {

        logging  = new Logging(JwtTokenUtil.class);

    }
    // Method for loading user from database (assume)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (USERNAME_PASSWORD_DEMO[0].equals(username)) { // If user do exists
            return new User(USERNAME_PASSWORD_DEMO[0], // create it again
                    USERNAME_PASSWORD_DEMO[1],
                    new ArrayList<>());
        } else {
            logging.logBack.warn("User is not found (username : " + username+")");
            throw new UsernameNotFoundException("User is not found (username : " + username+")");
        }
    }
}

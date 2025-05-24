package com.ttknpdev.understandjwthelloworld.configuration.jwt;

import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

/**
  # This is the best way if you want to use UserDetailsService for get login table on database
  JWTUserDetailsService implements the Spring Security UserDetailsService interface.
  *** It overrides the loadUserByUsername for fetching user details from the database using the username.
  *** The Spring Security Authentication Manager calls this method for getting the user details from the database
  when authenticating the user details provided by the user.
  Here we are getting the user details from a hardcoded User List.
// @Service
*/
public class JwtUserDetailsService implements UserDetailsService { // UserDetailsService is an interface that retrieves the user’s authentication

    private final Logging logging;
    // assume this is on your database
    private final String[] USERNAME_PASSWORD = {
            "Admin" ,
            "$2a$12$t/KZtF9AiRiC0tcleq5PAOd5OYxtaAbYrv4OCezsxIS0x3DaJv9.C" // is 1
            /**
               it is Bcrypt Hash
               can covert any string to Bcrypt by web (has many web for building it)
               ** default passwordEndcoder hash Bcrypt type
            */
    };

    public JwtUserDetailsService() {
        logging  = new Logging(JwtTokenUtil.class);
    }

    // Method for loading user from database (assume)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (USERNAME_PASSWORD[0].equals(username)) {
            return new org.springframework.security.core.userdetails.User(
                    USERNAME_PASSWORD[0],
                    USERNAME_PASSWORD[1],
                    convertRolesStringToGrantedAuthorityList("ROLE_ADMIN")
            );
        } else {
            logging.logBack.debug("Username is not found (username : {})", username);
            throw new UsernameNotFoundException("Username is not found (username : " + username+")");
        }
    }

    public static List<GrantedAuthority> convertRolesStringToGrantedAuthorityList(String rolesString) {
        return AuthorityUtils.createAuthorityList(rolesString);
    }
}

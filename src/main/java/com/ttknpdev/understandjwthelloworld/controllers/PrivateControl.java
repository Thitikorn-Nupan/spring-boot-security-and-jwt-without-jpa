package com.ttknpdev.understandjwthelloworld.controllers;

import com.ttknpdev.understandjwthelloworld.helper.JwtSpringSecurityContextHelper;
import com.ttknpdev.understandjwthelloworld.log.Logging;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.List;
/**
 This is basic api for leaning about Spring Security and JWT Configuration
 We will be configuring Spring Security and JWT for performing 2 operations
 Generating JWT - Expose a POST API with mapping /authenticate. On passing correct username and password it will generate a JSON Web Token(JWT)
 Validating JWT - If user tries to access GET API with mapping /hello. It will allow access only if request has a valid JSON Web Token(JWT)
*/
@RestController
@RequestMapping(value = "/api")
public class PrivateControl {
    private final Logging log;

    public PrivateControl() {
        log = new Logging(PrivateControl.class);
    }

    @GetMapping(value = {"/books" ,"/",""})
    private ResponseEntity<?> getBooks() {

        log.logBack.debug("http://localhost:8080/api/{books,/,} is accessed (Secure API)");
        // class inside method
        class Book {
            private String bid;
            private String title;
            private Double price;

            public Book(String bid, String title, Double price) {
                this.bid = bid;
                this.title = title;
                this.price = price;
            }

            public String getBid() {
                return bid;
            }

            public void setBid(String bid) {
                this.bid = bid;
            }

            public String getTitle() {
                return title;
            }

            public void setTitle(String title) {
                this.title = title;
            }

            public Double getPrice() {
                return price;
            }

            public void setPrice(Double price) {
                this.price = price;
            }
        }

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(List.of(
                                new Book("R001","let her go",300.00D),
                                new Book("R002","stay with me",250.00D))
                );
    }


    @GetMapping(value = "/principle")
    private ResponseEntity<Object> getPrinciple() {
        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(
                        JwtSpringSecurityContextHelper.getPrincipal()
                );
    }

    @GetMapping(value = "/roles")
    private ResponseEntity<Collection<GrantedAuthority>> getRoles() {
        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(
                        JwtSpringSecurityContextHelper.getAuthorities()
                );
    }

    @GetMapping(value = "/details")
    private ResponseEntity<Object> getDetails() {
        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(
                        JwtSpringSecurityContextHelper.getWebAuthenticationDetails()
                );
    }
}

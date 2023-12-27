package com.ttknpdev.understandjwthelloworld.entities;
import java.io.Serializable;
/*
   (Just showing TOKEN like java POJO )
   This is class is required for creating a response containing the JWT to be returned to the user.
*/
public class JwtResponse { // implements Serializable
    // private static final long serialVersionUID = -8091879091924046844L;
    private final String JWT;
    public JwtResponse(String JWT) {
        this.JWT = JWT;
    }
    public String getJWT() {
        return this.JWT;
    }

    @Override
    public String toString() {
        return "JwtResponse{" +
                "JWT='" + JWT + '\'' +
                '}';
    }
}

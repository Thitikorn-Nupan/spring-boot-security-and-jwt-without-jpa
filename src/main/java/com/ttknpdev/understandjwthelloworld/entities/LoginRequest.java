package com.ttknpdev.understandjwthelloworld.entities;

/**
    This class is required for storing the username and password we recieve from the client.
*/
public class LoginRequest { // Serializable

    // private static final long serialVersionUID = 5926468583005150707L;
    private String username;
    private String password;


    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return "JwtRequest{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}

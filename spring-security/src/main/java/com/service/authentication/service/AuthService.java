package com.service.authentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.service.authentication.client.UserClient;

@Service
public class AuthService {

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserClient userClient;

    public String generateToken(String username) {
    	System.out.println("Generate Token");
        return jwtService.generateToken(username);
    }

    public void validateToken(String token,int userId) {
    	String user = userClient.readUseremailById(userId);
        jwtService.isTokenValid(token, user);
    }

}
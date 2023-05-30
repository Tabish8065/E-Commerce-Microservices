package com.service.authentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.service.authentication.model.UserModel;
import com.service.authentication.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService service;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/token")
    public String getToken(@RequestBody UserModel authRequest) {
    	
    	System.out.println("UserModel : "+authRequest.getName()+" "+authRequest.getPassword());
    	
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authenticate.isAuthenticated()) {
        	System.out.println("33 Controller");
            return service.generateToken(authRequest.getUsername());
        } else {
            throw new RuntimeException("Invalid access");
        }
        
    }

    @GetMapping("/validate")
    public void validateToken(@RequestParam("token") String token, @RequestParam("userId") int userId) {
        service.validateToken(token, userId);
        System.out.println("Token is valid");
    }
    
    @GetMapping("/res")
    public String protec() {
    	return "Valid";
    }
    
    @GetMapping("/pro")
    public String protect() {
    	return "Pro";
    }
}
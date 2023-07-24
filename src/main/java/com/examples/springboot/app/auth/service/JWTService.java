package com.examples.springboot.app.auth.service;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.Claims;

public interface JWTService {

	
	public String create(Authentication auth)throws JsonProcessingException;
	public boolean validate(String token);
	public Claims getClaims(String token);
	public String getUsername(String token);
	public Collection<? extends GrantedAuthority> getRoles(String token) throws java.io.IOException;
	public String resolver(String token);
	
	
}

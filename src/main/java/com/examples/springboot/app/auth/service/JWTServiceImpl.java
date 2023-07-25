package com.examples.springboot.app.auth.service;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import com.examples.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTServiceImpl implements JWTService {
	
	private static final Key SECRET_KEY = null;
	SecretKey secretKey = new SecretKeySpec("algunaLlaveSecreta.12345".getBytes(), 
			SignatureAlgorithm.HS256.getJcaName());

	public static final long EXPIRATION_DATE =  3600000;
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	
	
	@Override
	public String create(Authentication auth) throws JsonProcessingException {
		String username = ((User) auth.getPrincipal()).getUsername();
		
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		
		Claims claims =Jwts.claims();
		claims.put("authorities",new ObjectMapper().writeValueAsString(roles));
		
		 String token = Jwts.builder()
				 .setClaims(claims)
                 .setSubject(username)
                 .signWith(SECRET_KEY)
                 .setIssuedAt(new Date())
                 .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
                 .compact();
		return null;
	}

	@Override
	public boolean validate(String token) {

		try {
			
			getClaims(token);
			return true;
		} catch (JwtException e) {
			return false;
		}

	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts.parser()
				.setSigningKey("algunaLlaveSecreta.12345".getBytes())
				.parseClaimsJws(resolver(token))
				.getBody();
		return claims;
	}

	@Override
	public String getUsername(String token) {
		
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws java.io.IOException {
		Object roles = getClaims(token).get("authorities");
		
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString(), SimpleGrantedAuthority[].class));
				
		
		return authorities;
	}

	@Override
	public String resolver(String token) {
		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");
		}
		return null;
	}

}

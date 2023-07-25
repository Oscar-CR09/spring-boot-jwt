package com.examples.springboot.app.auth.filter;

import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import com.examples.springboot.app.auth.service.JWTService;
import com.examples.springboot.app.auth.service.JWTServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager,JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
		
		if (!requiresAuthentication( header)) {
			chain.doFilter(request, response);
			return;
		}
		
	
		UsernamePasswordAuthenticationToken authentication = null;
		if (jwtService.validate(header)) {
		
			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null,jwtService.getRoles(header));
		}
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
		
	}

	protected boolean requiresAuthentication(String header) {
		if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}
}

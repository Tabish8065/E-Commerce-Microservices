package com.service.authentication.filter;

import java.io.IOException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.reactive.HandlerMapping;

import com.service.authentication.client.UserClient;
import com.service.authentication.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class AuthFilter extends OncePerRequestFilter {

	@Autowired
	private JwtService jwtService;
	
	@Autowired
	private UserDetailsService detailsService;
	
	@Autowired
	private UserClient userClient;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		final String token = authHeader.substring(7);
		final String username = jwtService.extractUsername(token);
		
		if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			
//			Map<String, String> map = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
//			
//			int userId = Integer.valueOf(map.get("user_id"));
//			String userFetched = userClient.readUseremailById(userId);
//			
//			System.out.println("Auth Filter " +userId+ " " +userFetched);
			
			UserDetails user = detailsService.loadUserByUsername(username);
			
			if(jwtService.isTokenValid(token, user.getUsername())) {
				UserDetails userDetail = detailsService.loadUserByUsername(username);
				
				UsernamePasswordAuthenticationToken authenticationToken = 
						new UsernamePasswordAuthenticationToken(userDetail,
								null,
								userDetail.getAuthorities());
				
				authenticationToken.setDetails(
						new WebAuthenticationDetailsSource()
						.buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			}
		}
		
		filterChain.doFilter(request, response);

	}

}

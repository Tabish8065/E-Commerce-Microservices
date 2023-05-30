package com.gateway.api.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import com.gateway.api.client.SecurityClient;
import com.gateway.api.routes.RouteValidator;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthFilter.class);

	@Autowired
	private RouteValidator routeValidator;
	
	@Autowired
	private SecurityClient securityClient;
	

    public AuthFilter() {
        super(Config.class);
    }
	
	@Override
	public GatewayFilter apply(Config config) { 
		// TODO Auto-generated method stub
		return ((exchange, chain) -> {
			
			if(routeValidator.isSecured.test(exchange.getRequest())) {
				logger.warn("Accessing secured website");
				
				//Header has token or not
				if(!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
					throw new RuntimeException("Header Missing");
				}
				
				String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
				logger.warn("Auth Header Retrived : "+authHeader);
				
				if(authHeader == null || !authHeader.startsWith("Bearer ")) {
					throw new RuntimeException("No header present");
				}
				
				try {
					String uid = exchange.getRequest().getQueryParams().getFirst("userId");
					logger.warn("Uid Retrived : "+uid);
					//securityClient.validateToken(authHeader.substring(7));
					securityClient.validateToken(authHeader.substring(7), Integer.parseInt(uid));
				}catch (Exception e) {
					
					System.out.print("Error\n");
					System.out.println(e.getMessage());
					throw new RuntimeException(e);
					
				}
				
			}
			
			return chain.filter(exchange);
		});
	}
	
	public static class Config {

    }
}

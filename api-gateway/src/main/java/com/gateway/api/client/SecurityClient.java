package com.gateway.api.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "spring-security", url = "http://localhost:9898/auth")
public interface SecurityClient {
//	
//	@GetMapping("/validate")
//    public String validateToken(@RequestParam("token") String token);

	@GetMapping("/validate")
	public void validateToken(@RequestParam("token") String token, @RequestParam("userId") int userId);

}

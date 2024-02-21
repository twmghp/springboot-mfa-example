package wm.springbootmfaexample.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import wm.springbootmfaexample.dto.ProtectedContentResponse;

@RestController
public class ProtectedContentController {

	@GetMapping("/")
	public ProtectedContentResponse getProtectedContent(Authentication authentication) {
		return ProtectedContentResponse.builder().username("user").content("content").build();
	}

}

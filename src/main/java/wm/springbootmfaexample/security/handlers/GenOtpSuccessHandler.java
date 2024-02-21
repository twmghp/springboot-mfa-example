package wm.springbootmfaexample.security.handlers;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import wm.springbootmfaexample.model.CustomUser;
import wm.springbootmfaexample.service.MfaService;

public class GenOtpSuccessHandler implements AuthenticationSuccessHandler {

	private final MfaService mfaService;

	public GenOtpSuccessHandler(MfaService mfaService) {
		this.mfaService = mfaService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		if (authentication.getPrincipal().getClass().isAssignableFrom(CustomUser.class))
			mfaService.generateOtp((CustomUser) authentication.getPrincipal());
	}

}

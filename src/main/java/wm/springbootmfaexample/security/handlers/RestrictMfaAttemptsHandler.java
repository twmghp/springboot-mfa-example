package wm.springbootmfaexample.security.handlers;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class RestrictMfaAttemptsHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

	private int maxAttempts;

	public RestrictMfaAttemptsHandler(int maxAttempts) {
		this.maxAttempts = maxAttempts;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		Integer attempts = (Integer) request.getSession().getAttribute("MFA_STAGE_ATTEMPTS");
		attempts = attempts == null ? 1 : attempts + 1;
		if (attempts > maxAttempts) {
			clearAuthentication(request, response);
			response.setStatus(HttpStatus.FORBIDDEN.value());

		}
		else {
			request.getSession().setAttribute("MFA_STAGE_ATTEMPTS", attempts);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
		}

	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		request.getSession().setAttribute("MFA_STAGE_ATTEMPTS", 0);
	}

	private void clearAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		SecurityContext context = SecurityContextHolder.getContext();
		context.setAuthentication(null);
		this.securityContextRepository.saveContext(context, request, response);
	}

}

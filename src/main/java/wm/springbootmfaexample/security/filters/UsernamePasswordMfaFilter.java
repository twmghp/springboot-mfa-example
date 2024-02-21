package wm.springbootmfaexample.security.filters;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import wm.springbootmfaexample.dto.LoginRequest;
import wm.springbootmfaexample.security.tokens.UsernamePasswordMfaToken;
import wm.springbootmfaexample.util.JsonUtil;

public class UsernamePasswordMfaFilter extends AbstractAuthenticationProcessingFilter {

	private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
			HttpMethod.POST.name());

	public UsernamePasswordMfaFilter() {
		super(DEFAULT_REQUEST_MATCHER);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		try {
			LoginRequest loginDto = JsonUtil.deserialize(request.getInputStream(), LoginRequest.class);
			UsernamePasswordMfaToken authRequest = new UsernamePasswordMfaToken(loginDto.getUsername(),
					loginDto.getPassword());
			Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
			return authentication;
		}
		catch (StreamReadException | DatabindException e) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			throw new AuthenticationServiceException("Unable to parse JSON", e);
		}
	}

}

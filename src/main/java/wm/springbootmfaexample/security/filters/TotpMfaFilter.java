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
import wm.springbootmfaexample.dto.SubmitTokenRequest;
import wm.springbootmfaexample.security.tokens.TotpMfaToken;
import wm.springbootmfaexample.util.JsonUtil;

public class TotpMfaFilter extends AbstractAuthenticationProcessingFilter {

	private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher("/totp",
			HttpMethod.POST.name());

	public TotpMfaFilter() {
		super(DEFAULT_REQUEST_MATCHER);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		try {
			SubmitTokenRequest submitTokenRequest = JsonUtil.deserialize(request.getInputStream(),
					SubmitTokenRequest.class);
			TotpMfaToken authRequest = new TotpMfaToken(submitTokenRequest.getToken());
			return this.getAuthenticationManager().authenticate(authRequest);

		}
		catch (StreamReadException | DatabindException e) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			throw new AuthenticationServiceException("Unable to parse JSON", e);
		}
	}

}

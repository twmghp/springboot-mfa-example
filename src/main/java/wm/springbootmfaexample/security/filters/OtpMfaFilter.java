package wm.springbootmfaexample.security.filters;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import wm.springbootmfaexample.dto.SubmitTokenRequest;
import wm.springbootmfaexample.security.tokens.OtpMfaToken;
import wm.springbootmfaexample.util.JsonUtil;

public class OtpMfaFilter extends AbstractAuthenticationProcessingFilter {

	private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher("/otp",
			HttpMethod.POST.name());

	public OtpMfaFilter() {
		super(DEFAULT_REQUEST_MATCHER);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		try {

			SubmitTokenRequest submitTokenRequest = JsonUtil.deserialize(request.getInputStream(),
					SubmitTokenRequest.class);
			OtpMfaToken authRequest = new OtpMfaToken(submitTokenRequest.getToken());
			return this.getAuthenticationManager().authenticate(authRequest);

		}
		catch (StreamReadException | DatabindException e) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			throw new AuthenticationServiceException("Unable to parse JSON", e);
		}
	}

}

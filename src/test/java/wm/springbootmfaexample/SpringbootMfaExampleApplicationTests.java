package wm.springbootmfaexample;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import wm.springbootmfaexample.dto.LoginRequest;
import wm.springbootmfaexample.dto.ProtectedContentResponse;
import wm.springbootmfaexample.dto.SubmitTokenRequest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SpringbootMfaExampleApplicationTests {

	private final String TOTP_BASE32_KEY = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";

	private final String OTP_TOKEN = "123456";

	private final String WRONG_OTP_TOKEN = "123455";

	@Value("${multifactorauth.otp.timeout-sec:5}")
	private int OTP_TOKEN_TIMEOUT_SECONDS;

	@Value("${multifactorauth.max-attempts:3}")
	private int MFA_MAX_ATTEMPTS = 3;

	@LocalServerPort
	private int port;

	@Autowired
	private TestRestTemplate testRestTemplate;

	private HttpHeaders cookieHeaders = new HttpHeaders();

	private ResponseEntity<Void> login(String username, String password) {
		LoginRequest loginRequest = LoginRequest.builder().username(username).password(password).build();
		ResponseEntity<Void> response = testRestTemplate.postForEntity("/login",
				new HttpEntity<>(loginRequest, cookieHeaders), Void.class);
		if (response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)) {
			cookieHeaders.clear();
			cookieHeaders.addAll(HttpHeaders.COOKIE, response.getHeaders().get(HttpHeaders.SET_COOKIE));
		}
		return response;
	}

	private ResponseEntity<Void> totp(String code) {
		SubmitTokenRequest submitTokenRequest = SubmitTokenRequest.builder().token(code).build();
		HttpEntity<SubmitTokenRequest> httpEntity = new HttpEntity<>(submitTokenRequest, cookieHeaders);

		ResponseEntity<Void> response = testRestTemplate.postForEntity("/totp", httpEntity, Void.class);
		if (response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)) {
			cookieHeaders.clear();
			cookieHeaders.addAll(HttpHeaders.COOKIE, response.getHeaders().get(HttpHeaders.SET_COOKIE));
		}
		return response;
	}

	private ResponseEntity<Void> newOtp() {
		ResponseEntity<Void> response = testRestTemplate.postForEntity("/otp/new", new HttpEntity<>(cookieHeaders),
				Void.class);

		if (response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)) {
			cookieHeaders.clear();
			cookieHeaders.addAll(HttpHeaders.COOKIE, response.getHeaders().get(HttpHeaders.SET_COOKIE));
		}
		return response;
	}

	private ResponseEntity<Void> otp(String code) {
		SubmitTokenRequest submitTokenRequest = SubmitTokenRequest.builder().token(code).build();
		HttpEntity<SubmitTokenRequest> httpEntity = new HttpEntity<>(submitTokenRequest, cookieHeaders);

		ResponseEntity<Void> response = testRestTemplate.postForEntity("/otp", httpEntity, Void.class);
		if (response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)) {
			cookieHeaders.clear();
			cookieHeaders.addAll(HttpHeaders.COOKIE, response.getHeaders().get(HttpHeaders.SET_COOKIE));
		}
		return response;
	}

	private ResponseEntity<ProtectedContentResponse> getProtectedContent() {
		ResponseEntity<ProtectedContentResponse> response = testRestTemplate.exchange("/", HttpMethod.GET,
				new HttpEntity<>(cookieHeaders), ProtectedContentResponse.class);

		if (response.getHeaders().containsKey(HttpHeaders.SET_COOKIE)) {
			cookieHeaders.clear();
			cookieHeaders.addAll(HttpHeaders.COOKIE, response.getHeaders().get(HttpHeaders.SET_COOKIE));
		}
		return response;
	}

	@Test
	public void getProtectedContent_WithoutLogin_returns403() throws Exception {
		ResponseEntity<ProtectedContentResponse> response = testRestTemplate.getForEntity("/",
				ProtectedContentResponse.class);
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
	}

	@Test
	public void multiFactorLogin_Success_NoSessionFixation() throws Exception {
		// Login
		ResponseEntity<Void> loginResponse = login("user", "password");
		assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
		String cookie = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE).get(0);

		// Failed Totp
		String wrongTotpToken = String.valueOf(TimeBasedOneTimePasswordUtil.generateNumber(TOTP_BASE32_KEY, 0, 30));
		ResponseEntity<Void> totpResponse = totp(wrongTotpToken);
		assertEquals(HttpStatus.UNAUTHORIZED, totpResponse.getStatusCode());

		// Totp
		String totpToken = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(TOTP_BASE32_KEY);
		totpResponse = totp(totpToken);
		assertEquals(HttpStatus.OK, totpResponse.getStatusCode());
		assertNotEquals(cookie, totpResponse.getHeaders().get(HttpHeaders.SET_COOKIE).get(0));
		cookie = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE).get(0);

		// Wrong Otp
		ResponseEntity<Void> otpResponse = otp(WRONG_OTP_TOKEN);
		assertEquals(HttpStatus.UNAUTHORIZED, otpResponse.getStatusCode());

		// Otp
		otpResponse = otp(OTP_TOKEN);
		assertEquals(HttpStatus.OK, otpResponse.getStatusCode());
		assertNotEquals(cookie, otpResponse.getHeaders().get(HttpHeaders.SET_COOKIE).get(0));
		cookie = loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE).get(0);

		// Protected content
		ResponseEntity<ProtectedContentResponse> response = getProtectedContent();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals(response.getBody().getUsername(), "user");
		assertEquals(response.getBody().getContent(), "content");

	}

	@Test
	public void multiFactorLogin_Success_canObtainProtectedContent() throws Exception {
		// Login
		ResponseEntity<Void> loginResponse = login("user", "password");
		assertEquals(HttpStatus.OK, loginResponse.getStatusCode());

		// Totp
		String totpToken = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(TOTP_BASE32_KEY);
		ResponseEntity<Void> totpResponse = totp(totpToken);
		assertEquals(HttpStatus.OK, totpResponse.getStatusCode());

		// Otp
		ResponseEntity<Void> otpResponse = otp(OTP_TOKEN);
		assertEquals(HttpStatus.OK, otpResponse.getStatusCode());

		// Protected content
		ResponseEntity<ProtectedContentResponse> response = getProtectedContent();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals(response.getBody().getUsername(), "user");
		assertEquals(response.getBody().getContent(), "content");

		// Cannot access multifactor auth routes
		totpToken = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(TOTP_BASE32_KEY);
		totpResponse = totp(totpToken);
		assertEquals(HttpStatus.UNAUTHORIZED, totpResponse.getStatusCode());

		otpResponse = otp(OTP_TOKEN);
		assertEquals(HttpStatus.UNAUTHORIZED, otpResponse.getStatusCode());
	}

	@Test
	public void multiFactorLogin_successWithMultipleAttempts_canObtainProtectedContent() throws Exception {
		// Login
		ResponseEntity<Void> loginResponse = login("user", "password");
		assertEquals(HttpStatus.OK, loginResponse.getStatusCode());

		// wrong totp
		String wrongTotpToken = String.valueOf(TimeBasedOneTimePasswordUtil.generateNumber(TOTP_BASE32_KEY, 0, 30));
		for (int i = 0; i < MFA_MAX_ATTEMPTS - 1; i++) {
			ResponseEntity<Void> totpResponse = totp(wrongTotpToken);
			assertEquals(HttpStatus.UNAUTHORIZED, totpResponse.getStatusCode());
		}
		// correct totp
		String correctTotpToken = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(TOTP_BASE32_KEY);
		ResponseEntity<Void> totpResponse = totp(correctTotpToken);
		assertEquals(HttpStatus.OK, totpResponse.getStatusCode());

		// Cannot access protected content
		ResponseEntity<ProtectedContentResponse> response = getProtectedContent();
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

		// wrong otp
		ResponseEntity<Void> otpResponse = otp(WRONG_OTP_TOKEN);
		assertEquals(HttpStatus.UNAUTHORIZED, otpResponse.getStatusCode());

		// otp timeout
		Thread.sleep((OTP_TOKEN_TIMEOUT_SECONDS + 1) * 1000);
		otpResponse = otp(OTP_TOKEN);
		assertEquals(HttpStatus.UNAUTHORIZED, otpResponse.getStatusCode());

		// Request for new Otp
		otpResponse = newOtp();
		assertEquals(HttpStatus.OK, otpResponse.getStatusCode());

		// correct otp
		otpResponse = otp(OTP_TOKEN);
		assertEquals(HttpStatus.OK, otpResponse.getStatusCode());

		// Protected content
		response = getProtectedContent();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals(response.getBody().getUsername(), "user");
		assertEquals(response.getBody().getContent(), "content");
	}

	@Test
	public void multiFactorLogin_toptExceedMaxAttempt_returns403() throws Exception {
		// Login
		ResponseEntity<Void> loginResponse = login("user", "password");
		assertEquals(HttpStatus.OK, loginResponse.getStatusCode());

		// Totp -first
		String wrongTotpToken = String.valueOf(TimeBasedOneTimePasswordUtil.generateNumber(TOTP_BASE32_KEY, 0, 30));
		for (int i = 0; i <= MFA_MAX_ATTEMPTS; i++) {
			ResponseEntity<Void> totpResponse = totp(wrongTotpToken);
			if (MFA_MAX_ATTEMPTS == i)
				assertEquals(HttpStatus.FORBIDDEN, totpResponse.getStatusCode());
			else
				assertEquals(HttpStatus.UNAUTHORIZED, totpResponse.getStatusCode());
		}

		// Cannot access protected content
		ResponseEntity<ProtectedContentResponse> response = getProtectedContent();
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
	}

	@Test
	public void multiFactorLogin_outOfOrderMultiFactorLogin_returns403() throws Exception {
		// Login
		ResponseEntity<Void> loginResponse = login("user", "password");
		assertEquals(HttpStatus.OK, loginResponse.getStatusCode());

		// Otp
		ResponseEntity<Void> otpResponse = otp(WRONG_OTP_TOKEN);
		assertEquals(HttpStatus.UNAUTHORIZED, otpResponse.getStatusCode());

		// Cannot access protected content
		ResponseEntity<ProtectedContentResponse> response = getProtectedContent();
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
	}

}

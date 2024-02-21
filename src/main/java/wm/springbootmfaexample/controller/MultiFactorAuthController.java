package wm.springbootmfaexample.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import wm.springbootmfaexample.model.CustomUser;
import wm.springbootmfaexample.security.tokens.TotpMfaToken;
import wm.springbootmfaexample.service.MfaService;

@RestController
public class MultiFactorAuthController {

	private final MfaService mfaService;

	public MultiFactorAuthController(MfaService mfaService) {
		this.mfaService = mfaService;
	}

	@PostMapping("/otp/new")
	public void requestNewOtp(TotpMfaToken authentication, HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		if (authentication != null && authentication.isStageAuthenticated()) {
			CustomUser user = (CustomUser) authentication.getPrincipal();
			mfaService.generateOtp(user);
		}
	}

}

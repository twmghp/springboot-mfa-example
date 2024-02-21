package wm.springbootmfaexample.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@AllArgsConstructor
@Getter
public class LoginRequest {

	private String username;

	private String password;

	protected LoginRequest() {
		super();
	}

}

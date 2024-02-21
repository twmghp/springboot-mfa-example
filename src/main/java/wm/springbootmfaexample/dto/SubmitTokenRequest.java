package wm.springbootmfaexample.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@AllArgsConstructor
public class SubmitTokenRequest {

	protected SubmitTokenRequest() {
		super();
	}

	private String token;

}

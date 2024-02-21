package wm.springbootmfaexample.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@AllArgsConstructor
public class ProtectedContentResponse {

	private String username;

	private String content;

	protected ProtectedContentResponse() {
		super();
	}

}

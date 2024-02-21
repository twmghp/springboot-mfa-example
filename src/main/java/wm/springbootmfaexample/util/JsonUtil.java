package wm.springbootmfaexample.util;

import java.io.IOException;
import java.io.InputStream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {

	private static final ObjectMapper mapper = new ObjectMapper();

	public static String serialize(Object object) throws JsonProcessingException {
		return mapper.writeValueAsString(object);
	}

	public static <T> T deserialize(InputStream input, Class<T> clazz)
			throws StreamReadException, DatabindException, IOException {
		return mapper.readValue(input, clazz);
	}

}

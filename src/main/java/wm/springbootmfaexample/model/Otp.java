package wm.springbootmfaexample.model;

import java.time.Instant;

public record Otp(String username, String value, Instant genTimestamp) {
}

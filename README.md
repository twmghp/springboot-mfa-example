# springboot-mfa-example

A simple multifactor authentication reference setup for a JSON API server which was built with reference to the mfa example from the [official spring security sample repo](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/authentication/username-password/mfa).

# Authentication flow

1. Username, password login - `user:password`
2. TOTP token - Base32 secret compatible with Google authenticator: `QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK`
3. OTP token - default: `123456` with 5 seconds timeout
4. Access protected content

[Postman collection here](postman/MFA.postman_collection.json)

# Additional features added to the spring security sample

- Login using JSON
- Implement multifactor authentication with a custom `AuthenticationProvider` instead of using rest controllers
  - Added a custom `Authentication` object to add function
- Limit authentication attempts at each stage using custom `AuthenticationFailureHandler` and `AuthenticationSuccessHandler`
- Enforce authentication order
- OTP refresh

# Note

- This is a practice project you will need to additonal configuration/features (eg. secure cookies, OTP generation/sending ...)

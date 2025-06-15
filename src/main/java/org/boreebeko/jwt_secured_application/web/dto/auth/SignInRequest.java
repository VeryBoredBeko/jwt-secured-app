package org.boreebeko.jwt_secured_application.web.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignInRequest {

    @Size(min = 5, max = 50)
    @NotBlank
    private String username;

    @Size(min = 8)
    @NotBlank
    private String password;
}

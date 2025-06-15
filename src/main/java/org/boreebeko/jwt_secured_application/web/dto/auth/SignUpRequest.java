package org.boreebeko.jwt_secured_application.web.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {

    @Size(min = 5, max = 50)
    @NotBlank
    private String username;

    @Size(min = 5, max = 50)
    @NotBlank
    @Email
    private String email;

    @Size(min = 8)
    private String password;
}

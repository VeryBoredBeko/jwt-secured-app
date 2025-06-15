package org.boreebeko.jwt_secured_application.web.dto.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JWTAuthenticationResponse {

    private String token;
}

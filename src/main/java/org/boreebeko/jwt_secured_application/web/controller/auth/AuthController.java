package org.boreebeko.jwt_secured_application.web.controller.auth;

import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.exception.AuthenticationException;
import org.boreebeko.jwt_secured_application.service.auth.AuthenticationService;
import org.boreebeko.jwt_secured_application.web.dto.auth.SignInRequest;
import org.boreebeko.jwt_secured_application.web.dto.auth.SignUpRequest;
import org.boreebeko.jwt_secured_application.web.dto.auth.jwt.JWTAuthenticationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    public JWTAuthenticationResponse signUp(@RequestBody SignUpRequest request) {
        return authenticationService.signUp(request);
    }

    @PostMapping("/sign-in")
    public JWTAuthenticationResponse signIn(@RequestBody SignInRequest request) {
        return authenticationService.signIn(request);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JWTAuthenticationResponse> refresh(@RequestBody JWTAuthenticationResponse jwtAuthenticationResponse) {
        try {
            return new ResponseEntity<>(authenticationService.refresh(jwtAuthenticationResponse.getRefreshToken()), HttpStatus.OK);
        } catch (AuthenticationException exception) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }
}

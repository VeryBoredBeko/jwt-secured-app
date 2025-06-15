package org.boreebeko.jwt_secured_application.service.auth;

import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.domain.Role;
import org.boreebeko.jwt_secured_application.domain.SecurityUser;
import org.boreebeko.jwt_secured_application.domain.User;
import org.boreebeko.jwt_secured_application.web.dto.auth.SignInRequest;
import org.boreebeko.jwt_secured_application.web.dto.auth.SignUpRequest;
import org.boreebeko.jwt_secured_application.web.dto.auth.jwt.JWTAuthenticationResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserService userService;
    private final JWTService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationResponse signUp(SignUpRequest signUpRequest) {

        User newUser = new User();
        newUser.setUsername(signUpRequest.getUsername());
        newUser.setEmail(signUpRequest.getEmail());
        newUser.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        newUser.setRole(Role.USER);

        userService.create(newUser);

        String jws = jwtService.generateToken(new SecurityUser(newUser));
        return new JWTAuthenticationResponse(jws);
    }

    public JWTAuthenticationResponse signIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsername(),
                        signInRequest.getPassword()
                )
        );

        UserDetails user = userService
                .userDetailsService()
                .loadUserByUsername(signInRequest.getUsername());

        String jws = jwtService.generateToken(user);
        return new JWTAuthenticationResponse(jws);
    }
}

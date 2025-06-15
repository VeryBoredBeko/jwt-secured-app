package org.boreebeko.jwt_secured_application.service.auth;

import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.domain.Role;
import org.boreebeko.jwt_secured_application.domain.SecurityUser;
import org.boreebeko.jwt_secured_application.domain.User;
import org.boreebeko.jwt_secured_application.exception.AuthenticationException;
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

        String accessToken = jwtService.generateToken(new SecurityUser(newUser), JWTService.TokenType.ACCESS_TOKEN);
        String refreshToken = jwtService.generateToken(new SecurityUser(newUser), JWTService.TokenType.REFRESH_TOKEN);

        return new JWTAuthenticationResponse(accessToken, refreshToken);
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

        String accessToken = jwtService.generateToken(user, JWTService.TokenType.ACCESS_TOKEN);
        String refreshToken = jwtService.generateToken(user, JWTService.TokenType.REFRESH_TOKEN);

        return new JWTAuthenticationResponse(accessToken, refreshToken);
    }

    public JWTAuthenticationResponse refresh(String refreshToken) throws AuthenticationException {

        String username = jwtService.extractUsername(refreshToken, JWTService.TokenType.REFRESH_TOKEN);

        UserDetails user = userService
                .userDetailsService()
                .loadUserByUsername(username);

        if (jwtService.isTokenValid(refreshToken, user, JWTService.TokenType.REFRESH_TOKEN)) {

            String newAccessToken = jwtService.generateToken(user, JWTService.TokenType.ACCESS_TOKEN);
            String newRefreshToken = jwtService.generateToken(user, JWTService.TokenType.REFRESH_TOKEN);

            return new JWTAuthenticationResponse(newAccessToken, newRefreshToken);

        } else throw new AuthenticationException();
    }
}

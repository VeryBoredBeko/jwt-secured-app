package org.boreebeko.jwt_secured_application.web.controller;

import org.boreebeko.jwt_secured_application.exception.AuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@org.springframework.web.bind.annotation.ControllerAdvice
public class ControllerAdvice {

    public ResponseEntity<Void> handleAuthenticationException(AuthenticationException exception) {
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
}

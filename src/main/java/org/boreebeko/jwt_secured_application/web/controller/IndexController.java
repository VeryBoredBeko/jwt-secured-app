package org.boreebeko.jwt_secured_application.web.controller;

import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.service.auth.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/index")
@RequiredArgsConstructor
public class IndexController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<String> getIndex() {
        return ResponseEntity.ok("Hello, World!");
    }
}

package org.boreebeko.jwt_secured_application.service.auth;

import lombok.RequiredArgsConstructor;
import org.boreebeko.jwt_secured_application.domain.SecurityUser;
import org.boreebeko.jwt_secured_application.domain.User;
import org.boreebeko.jwt_secured_application.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User save(User user) {
        return userRepository.save(user);
    }

    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException();
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException();
        }

        return save(user);
    }

    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("There is no user with such username"));
    }

    public UserDetailsService userDetailsService() {
        return username -> new SecurityUser(getByUsername(username));
    }

    public User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }
}

package org.boreebeko.jwt_secured_application.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users")
@NoArgsConstructor
@Getter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Setter
    private String username;

    @Setter
    private String password;

    @Setter
    private String email;

    @Enumerated(value = EnumType.STRING)
    @Setter
    private Role role;
}

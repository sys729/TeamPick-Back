package com.main.spring.Entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User extends AuditingEntity{


    @Column(nullable = false,length = 100)
    private String username;

    @Column(nullable = false,length = 100)
    private String password;

    @Column(nullable = false,length = 100)
    private String email;

    @Column(nullable = false,length = 50)
    private String name;

    private int age;

    @Column(length = 50)
    private String role;
    @Column(length = 10)
    private String provider;
    @Column(length = 100)
    private String providerId;




}

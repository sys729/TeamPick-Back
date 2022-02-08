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
    private String username; //유저 아이디

    @Column(nullable = false,length = 100)
    private String password; // 비밀번호

    @Column(nullable = false,length = 100)
    private String email; // 이메일

    @Column(nullable = false,length = 50)
    private String name; // 이름

    private int age; //나이 (정수)

    @Column(length = 50)
    private String role; // 권한

    @Column(length = 10)
    private String provider;

    @Column(length = 100)
    private String providerId;


}

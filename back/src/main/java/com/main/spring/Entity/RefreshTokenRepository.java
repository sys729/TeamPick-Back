package com.main.spring.Entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Boolean existsByUsername(String username);
    RefreshToken findByUsername(String username);
    RefreshToken deleteTokenByUsername(String username);
}

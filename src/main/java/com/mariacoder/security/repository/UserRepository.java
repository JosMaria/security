package com.mariacoder.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mariacoder.security.user.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    
    Optional<User> findByUsername(String username);
}

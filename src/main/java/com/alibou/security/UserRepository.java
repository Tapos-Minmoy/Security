package com.alibou.security;

import com.alibou.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {


    Optional<UserDetails> findByEmail(String email);
}

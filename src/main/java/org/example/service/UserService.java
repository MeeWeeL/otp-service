package org.example.service;

import org.example.model.User;
import org.example.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;

    public UserService(UserRepository userRepo, PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.encoder = encoder;
    }

    public User register(User user) {
        if(user.getRole().equals("ADMIN") && userRepo.existsByRole("ADMIN")) {
            throw new RuntimeException("Admin already exists");
        }
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepo.save(user);
    }
}

package com.cos.jwt.auth;

import com.cos.jwt.model.Users;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 로 폼 로그인 시 동작 안 할 것, 시큐리티 세팅에 명시
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService.loadUserByUsername");
        Users userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity = " + userEntity);
        return new PrincipalDetails(userEntity);
    }
}

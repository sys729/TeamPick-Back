package com.main.spring.security.auth;


import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//유저 정보를 가져오는 인터페이스 구현
// login 요청 시 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername이 호출됨
@Slf4j
@RequiredArgsConstructor
@Service
public class DetailService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("security username = {}", username);

        User user = userRepository.findByUsername(username);
        if(user != null){
            return new CustomUserDetails(user);
        }
        return null;
    }

}

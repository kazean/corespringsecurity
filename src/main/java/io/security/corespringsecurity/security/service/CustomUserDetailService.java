package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service("customUserDetailService")
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final HttpServletRequest request;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if (account == null) {
            if (userRepository.countByUsername(username) == 0) {
                throw new UsernameNotFoundException("usernameNotFoundException");
            }
        }

        Set<String> userRoles = account.getUserRoles().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toSet());

        List<SimpleGrantedAuthority> grantedAuthorities = userRoles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new AccountContext(account, grantedAuthorities);
    }
}

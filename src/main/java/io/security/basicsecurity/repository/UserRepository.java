package io.security.basicsecurity.repository;

import io.security.basicsecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<Account, Long> {
    public Account findByUsername(String username);
}

package io.security.corespringsecurity.aopsecurity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AopMethodService {

    @Secured("ROLE_USER")
    public void methodSecured() {
        log.info("AopMethodService.methodSecured");
    }
}

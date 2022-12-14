package io.security.corespringsecurity.aopsecurity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AopPointcutService {

    public void pointcutSecured() {
        log.info("pointcutSecured");
    }

    public void notSecured() {
        log.info("notSecured");
    }
}

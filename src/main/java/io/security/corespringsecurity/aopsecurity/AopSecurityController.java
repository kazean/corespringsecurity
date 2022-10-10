package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AopSecurityController {
    private final AopMethodService aopMethodService;
    private final AopPointcutService aopPointcutService;
    private final AopLiveMethodService aopLiveMethodService;

    @GetMapping("/preAuthorized")
    @PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username")
    public String preAuthorized(Model model, AccountDto account) {
        log.info("account.username={}", account.getUsername());
        model.addAttribute("method", "Success @PreAuthorize");
        return "aop/method";
    }

    @GetMapping("/methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");
        return "aop/method";
    }

    @GetMapping("/pointcutSecured")
    public String pointcutSecured1(Model model) {
        aopPointcutService.notSecured();
        aopPointcutService.pointcutSecured();

        model.addAttribute("method", "Success PointcutSecured");
        return "aop/method";
    }

    @GetMapping("/liveMethodSecured")
    public String liveMethodSecured(Model model){
        aopLiveMethodService.liveMethodSecured();
        model.addAttribute("method", "Success LiveMethodSecured");
        return "aop/method";
    }

}

package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    @GetMapping("/mypage")
    public String myPage() {
        userService.order();
        return "user/mypage";
    }

}

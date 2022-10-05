package io.security.corespringsecurity.controller.user;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/messages")
    public String messages() {
        return "user/messages";
    }

    @PostMapping("/api/messages")
    @ResponseBody
    public ResponseEntity apiMessages() {

        return ResponseEntity.ok().body("ok");
    }
}

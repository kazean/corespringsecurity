package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    /**
     * 회원가입
     * @return
     */
    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        userService.createUser(account);

        return "redirect:/";
    }

    /**
     * 로그인
     * @param error
     * @param exception
     * @param model
     * @return
     */
    @RequestMapping(value = {"/login", "/api/login"})
//    @RequestMapping(value = {"/login"})
    public String login(@RequestParam(value = "error", required = false) String error
            ,@RequestParam(value = "exception", required = false) String exception
            , Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
//        return "user/login/login";
        return "login";
    }

    /**
     * 로그아웃
     * @param request
     * @param response
     * @return
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
//        return "redirect:/api/login";
    }

    @GetMapping(value = {"/denied", "/api/deined"})
    public String denied(@RequestParam(value = "exception", required = false) String exception
            , Principal principal, Model model) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Account principal = (Account) authentication.getPrincipal();
        Account account = null;
        if (principal instanceof UsernamePasswordAuthenticationToken) {
            account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

        }else if(principal instanceof AjaxAuthenticationToken){
            account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
        }

//        model.addAttribute("username", principal.getUsername());
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}

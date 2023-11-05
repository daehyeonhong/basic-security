package io.security.basicsecurity.presentation;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class SecurityController {
    @GetMapping(value = "/")
    public String index(final HttpServletRequest request) {
        log.info("requestURL: {}, Agent: {}", request.getRequestURL(), request.getHeader(HttpHeaders.USER_AGENT));
        return "home";
    }

    @GetMapping(value = "/loginPage")
    public String loginPage() {
        return "loginPage";
    }
}

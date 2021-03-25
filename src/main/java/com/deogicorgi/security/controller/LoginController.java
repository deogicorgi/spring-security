package com.deogicorgi.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class LoginController {

    @RequestMapping("/login")
    public String login() {
        return "form/login.html";
    }

    @RequestMapping(value = "/login/pross", method = RequestMethod.POST)
    public String loginProcess() {
        System.out.println("process");
        return "form/login.html";
    }
}
